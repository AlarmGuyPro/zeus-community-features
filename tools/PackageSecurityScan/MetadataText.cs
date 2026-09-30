// SPDX-License-Identifier: GPL-2.0-or-later
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace PackageSecurityScan;

/// <summary>
/// Turns metadata handles and signature blobs into stable display text. Every
/// recursive walk is depth-bounded and every blob is size-bounded, because a
/// crafted assembly can contain cyclic nesting or deeply nested signatures that
/// would otherwise overflow the stack.
/// </summary>
internal sealed class MetadataText : ISignatureTypeProvider<string, object?>
{
    private const int MaxDepth = 64;
    private const int MaxBlobBytes = 16 * 1024;
    private readonly Dictionary<EntityHandle, string> _typeNames = [];
    private int _specDepth;

    public MetadataText(MetadataReader reader) => Reader = reader;

    public MetadataReader Reader { get; }

    public static bool IsGenerated(string name) => name.Contains('<', StringComparison.Ordinal) &&
        !string.Equals(name, "<Module>", StringComparison.Ordinal);

    /// <summary>Strips generic instantiation arguments: <c>List`1&lt;System.String&gt;</c> → <c>List`1</c>.</summary>
    public static string GenericDefinition(string typeText)
    {
        var index = typeText.IndexOf('<', StringComparison.Ordinal);
        return index > 0 ? typeText[..index] : typeText;
    }

    public BlobReader Blob(BlobHandle handle)
    {
        var reader = Reader.GetBlobReader(handle);
        if (reader.Length > MaxBlobBytes)
        {
            throw new BadImageFormatException($"Signature blob of {reader.Length} bytes exceeds the scanner limit");
        }
        return reader;
    }

    public string TypeRef(TypeReferenceHandle handle)
    {
        if (_typeNames.TryGetValue(handle, out var cached)) return cached;
        var name = TypeRef(handle, 0);
        _typeNames[handle] = name;
        return name;
    }

    private string TypeRef(TypeReferenceHandle handle, int depth)
    {
        if (depth > MaxDepth) throw new BadImageFormatException("Type reference nesting is too deep or cyclic");
        var reference = Reader.GetTypeReference(handle);
        var name = Reader.GetString(reference.Name);
        if (reference.ResolutionScope.Kind == HandleKind.TypeReference)
        {
            return TypeRef((TypeReferenceHandle)reference.ResolutionScope, depth + 1) + "+" + name;
        }
        var ns = Reader.GetString(reference.Namespace);
        return ns.Length == 0 ? name : ns + "." + name;
    }

    /// <summary>The assembly (or module) a type reference resolves to; empty for the current module.</summary>
    public string TypeRefScope(TypeReferenceHandle handle)
    {
        var current = handle;
        for (var depth = 0; depth <= MaxDepth; depth++)
        {
            var scope = Reader.GetTypeReference(current).ResolutionScope;
            switch (scope.Kind)
            {
                case HandleKind.TypeReference:
                    current = (TypeReferenceHandle)scope;
                    continue;
                case HandleKind.AssemblyReference:
                    return Reader.GetString(Reader.GetAssemblyReference((AssemblyReferenceHandle)scope).Name);
                case HandleKind.ModuleReference:
                    return "module:" + Reader.GetString(Reader.GetModuleReference((ModuleReferenceHandle)scope).Name);
                default:
                    return "";
            }
        }
        throw new BadImageFormatException("Type reference nesting is too deep or cyclic");
    }

    public string TypeDef(TypeDefinitionHandle handle)
    {
        if (_typeNames.TryGetValue(handle, out var cached)) return cached;
        var name = TypeDef(handle, 0);
        _typeNames[handle] = name;
        return name;
    }

    private string TypeDef(TypeDefinitionHandle handle, int depth)
    {
        if (depth > MaxDepth) throw new BadImageFormatException("Type definition nesting is too deep or cyclic");
        var definition = Reader.GetTypeDefinition(handle);
        var name = Reader.GetString(definition.Name);
        var declaring = definition.GetDeclaringType();
        if (!declaring.IsNil) return TypeDef(declaring, depth + 1) + "+" + name;
        var ns = Reader.GetString(definition.Namespace);
        return ns.Length == 0 ? name : ns + "." + name;
    }

    public string TypeSpec(TypeSpecificationHandle handle)
    {
        if (++_specDepth > MaxDepth)
        {
            _specDepth = 0;
            throw new BadImageFormatException("Type specification nesting is too deep or cyclic");
        }
        try
        {
            var spec = Reader.GetTypeSpecification(handle);
            _ = Blob(spec.Signature);
            return spec.DecodeSignature(this, null);
        }
        finally
        {
            _specDepth = Math.Max(0, _specDepth - 1);
        }
    }

    /// <summary>Display text for any TypeDef/TypeRef/TypeSpec handle.</summary>
    public string Type(EntityHandle handle) => handle.Kind switch
    {
        HandleKind.TypeDefinition => TypeDef((TypeDefinitionHandle)handle),
        HandleKind.TypeReference => TypeRef((TypeReferenceHandle)handle),
        HandleKind.TypeSpecification => TypeSpec((TypeSpecificationHandle)handle),
        _ => "",
    };

    /// <summary>
    /// The owning type of a MemberRef parent, as (generic-definition name used for
    /// rule matching, full display text used for fingerprints).
    /// </summary>
    public (string Type, string Text) MemberParent(EntityHandle parent)
    {
        switch (parent.Kind)
        {
            case HandleKind.TypeDefinition:
            case HandleKind.TypeReference:
            case HandleKind.TypeSpecification:
                var text = Type(parent);
                return (GenericDefinition(text), text);
            case HandleKind.ModuleReference:
                var module = "[module]" + Reader.GetString(Reader.GetModuleReference((ModuleReferenceHandle)parent).Name);
                return (module, module);
            case HandleKind.MethodDefinition:
                var owner = TypeDef(Reader.GetMethodDefinition((MethodDefinitionHandle)parent).GetDeclaringType());
                return (owner, owner);
            default:
                return ("", "");
        }
    }

    public string MemberRefSignature(MemberReference member)
    {
        var blob = Blob(member.Signature);
        if (blob.Length == 0) return "";
        return member.GetKind() switch
        {
            MemberReferenceKind.Method => MethodSignature(member.DecodeMethodSignature(this, null)),
            MemberReferenceKind.Field => " : " + member.DecodeFieldSignature(this, null),
            _ => "",
        };
    }

    public static string MethodSignature(MethodSignature<string> signature)
    {
        var generic = signature.GenericParameterCount > 0 ? $"<{signature.GenericParameterCount}>" : "";
        return $"{generic}({string.Join(",", signature.ParameterTypes)}) : {signature.ReturnType}";
    }

    public string MethodDefSignature(MethodDefinition method)
    {
        _ = Blob(method.Signature);
        return MethodSignature(method.DecodeSignature(this, null));
    }

    public string FieldDefType(FieldDefinition field)
    {
        _ = Blob(field.Signature);
        return field.DecodeSignature(this, null);
    }

    /// <summary>
    /// Resolves a call/newobj/ldftn token to (declaring type, method name). The token is
    /// range-checked against the table so a crafted operand cannot read out of bounds.
    /// </summary>
    public (string Type, string Name)? ResolveMethodToken(int token)
    {
        var table = (TableIndex)(token >>> 24);
        var row = token & 0xFFFFFF;
        if (row < 1) throw new BadImageFormatException($"Invalid method token 0x{token:X8}");
        switch (table)
        {
            case TableIndex.MemberRef:
                CheckRow(TableIndex.MemberRef, row, token);
                var member = Reader.GetMemberReference(MetadataTokens.MemberReferenceHandle(row));
                return (MemberParent(member.Parent).Type, Reader.GetString(member.Name));
            case TableIndex.MethodDef:
                CheckRow(TableIndex.MethodDef, row, token);
                var method = Reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(row));
                return (TypeDef(method.GetDeclaringType()), Reader.GetString(method.Name));
            case TableIndex.MethodSpec:
                CheckRow(TableIndex.MethodSpec, row, token);
                var spec = Reader.GetMethodSpecification(MetadataTokens.MethodSpecificationHandle(row));
                var inner = MetadataTokens.GetToken(spec.Method);
                if ((TableIndex)(inner >>> 24) == TableIndex.MethodSpec)
                {
                    throw new BadImageFormatException("MethodSpec refers to another MethodSpec");
                }
                return ResolveMethodToken(inner);
            default:
                throw new BadImageFormatException($"Call operand 0x{token:X8} is not a method token");
        }
    }

    public void CheckRow(TableIndex table, int row, int token)
    {
        if (row < 1 || row > Reader.GetTableRowCount(table))
        {
            throw new BadImageFormatException($"Metadata token 0x{token:X8} is out of range");
        }
    }

    // ISignatureTypeProvider
    public string GetArrayType(string elementType, ArrayShape shape) =>
        $"{elementType}[{new string(',', Math.Max(0, shape.Rank - 1))}]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) =>
        $"method[{signature.Header.CallingConvention}] {MethodSignature(signature)}";
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) =>
        $"{genericType}<{string.Join(",", typeArguments)}>";
    public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
    public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) =>
        $"{unmodifiedType} {(isRequired ? "modreq" : "modopt")}({modifier})";
    public string GetPinnedType(string elementType) => elementType + " pinned";
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
        TypeDef(handle);
    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
        TypeRef(handle);
    public string GetTypeFromSpecification(MetadataReader reader, object? genericContext,
        TypeSpecificationHandle handle, byte rawTypeKind) => TypeSpec(handle);
}
