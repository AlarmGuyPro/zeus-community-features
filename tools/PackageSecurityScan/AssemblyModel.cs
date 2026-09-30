// SPDX-License-Identifier: GPL-2.0-or-later
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace PackageSecurityScan;

internal sealed record TypeRefRecord(string Scope, string FullName);
internal sealed record TypeDefRecord(string FullName, string BaseType, bool IsGenerated);
internal sealed record MemberRefRecord(string ParentType, string ParentText, string Name, string Signature)
{
    public string Display => $"{ParentType}::{Name}";
}
internal sealed record MethodRecord(string DeclaringType, string Name, string Signature, bool IsGenerated,
    string? IlHash, string? PInvokeTarget)
{
    public string Display => $"{DeclaringType}::{Name}{Signature}";
}
internal sealed record FieldRecord(string DeclaringType, string Name, string FieldType, bool IsGenerated,
    int RvaSize, string? RvaHash, string? ConstantString);
internal sealed record ResourceRecord(string Name, byte[]? Bytes, string? LinkedTo);
internal sealed record AttributeRecord(string CtorType, string Parent, string ValueHash, bool ParentGenerated,
    bool CtorIsExternal);

internal enum StringOrigin
{
    UserString,
    Constant,
    AttributeArgument,
}

internal sealed record ScannedString(string Value, StringOrigin Origin);

/// <summary>
/// Everything the rules and the rebuild comparison need from one managed
/// assembly, read with System.Reflection.Metadata. The assembly is parsed as
/// bytes and is never loaded into any runtime.
/// </summary>
internal sealed class AssemblyModel
{
    private const int FieldRvaHashLimit = 64 * 1024 * 1024;
    private const int MinAttributeRun = 4;

    public string? Name { get; private set; }
    public string? Version { get; private set; }
    public string? PublicKeyHash { get; private set; }
    public List<(string Name, string Version)> AssemblyRefs { get; } = [];
    public List<TypeRefRecord> TypeRefs { get; } = [];
    public List<TypeDefRecord> TypeDefs { get; } = [];
    public List<MemberRefRecord> MemberRefs { get; } = [];
    public List<MethodRecord> Methods { get; } = [];
    public List<FieldRecord> Fields { get; } = [];
    public List<ResourceRecord> Resources { get; } = [];
    public List<AttributeRecord> Attributes { get; } = [];
    public List<string> UserStrings { get; } = [];
    public List<ScannedString> Strings { get; } = [];
    public List<string> TimeBombs { get; } = [];
    public List<string> UnmanagedCalli { get; } = [];

    /// <summary>For each called "Type::Method", the declaring types of the methods that call it.</summary>
    public Dictionary<string, HashSet<string>> CallersByTarget { get; } = new(StringComparer.Ordinal);
    public bool ModuleHasStaticConstructor { get; private set; }

    public static AssemblyModel Read(byte[] bytes)
    {
        using var pe = new PEReader(ImmutableArray.Create(bytes));
        var reader = pe.GetMetadataReader();
        var text = new MetadataText(reader);
        var model = new AssemblyModel();
        model.ReadIdentity(reader);
        model.ReadTypeRefs(text);
        model.ReadMemberRefs(text);
        var methodNames = model.ReadTypesAndMembers(pe, text);
        model.ReadUserStrings(reader);
        model.ReadResources(pe, reader);
        model.ReadAttributes(text, methodNames);
        return model;
    }

    private void ReadIdentity(MetadataReader reader)
    {
        if (reader.IsAssembly)
        {
            var assembly = reader.GetAssemblyDefinition();
            Name = reader.GetString(assembly.Name);
            Version = assembly.Version.ToString();
            var key = reader.GetBlobBytes(assembly.PublicKey);
            PublicKeyHash = key.Length == 0 ? "" : Text.Sha256(key)[..16];
        }
        foreach (var handle in reader.AssemblyReferences)
        {
            var reference = reader.GetAssemblyReference(handle);
            AssemblyRefs.Add((reader.GetString(reference.Name), reference.Version.ToString()));
        }
    }

    private void ReadTypeRefs(MetadataText text)
    {
        foreach (var handle in text.Reader.TypeReferences)
        {
            TypeRefs.Add(new TypeRefRecord(text.TypeRefScope(handle), text.TypeRef(handle)));
        }
    }

    private void ReadMemberRefs(MetadataText text)
    {
        foreach (var handle in text.Reader.MemberReferences)
        {
            var member = text.Reader.GetMemberReference(handle);
            var (type, parentText) = text.MemberParent(member.Parent);
            MemberRefs.Add(new MemberRefRecord(type, parentText, text.Reader.GetString(member.Name),
                text.MemberRefSignature(member)));
        }
    }

    private Dictionary<EntityHandle, string> ReadTypesAndMembers(PEReader pe, MetadataText text)
    {
        var reader = text.Reader;
        // Owner names for custom-attribute parents that do not expose their owner directly.
        var owners = new Dictionary<EntityHandle, string>();
        var firstType = true;
        foreach (var typeHandle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(typeHandle);
            var typeName = text.TypeDef(typeHandle);
            var typeGenerated = MetadataText.IsGenerated(typeName);
            var baseType = type.BaseType.IsNil ? "" : text.Type(type.BaseType);
            TypeDefs.Add(new TypeDefRecord(typeName, baseType, typeGenerated));
            owners[typeHandle] = "type " + typeName;

            foreach (var methodHandle in type.GetMethods())
            {
                var method = reader.GetMethodDefinition(methodHandle);
                var name = reader.GetString(method.Name);
                var signature = text.MethodDefSignature(method);
                var display = $"{typeName}::{name}{signature}";
                if (firstType && name == ".cctor") ModuleHasStaticConstructor = true;

                string? pinvoke = null;
                if ((method.Attributes & MethodAttributes.PinvokeImpl) != 0)
                {
                    var import = method.GetImport();
                    var module = import.Module.IsNil
                        ? "?"
                        : reader.GetString(reader.GetModuleReference(import.Module).Name);
                    var entry = import.Name.IsNil ? name : reader.GetString(import.Name);
                    pinvoke = $"{module}!{entry}";
                }

                string? ilHash = null;
                if (method.RelativeVirtualAddress != 0)
                {
                    var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                    var il = body.GetILBytes() ?? [];
                    ilHash = Text.Sha256(il);
                    IlWalker.Walk(text, body, typeName, display, this);
                }
                Methods.Add(new MethodRecord(typeName, name, signature,
                    typeGenerated || MetadataText.IsGenerated(name), ilHash, pinvoke));
                owners[methodHandle] = "method " + display;
                foreach (var parameterHandle in method.GetParameters())
                {
                    var parameter = reader.GetParameter(parameterHandle);
                    owners[parameterHandle] = $"parameter {parameter.SequenceNumber} of {display}";
                }
                foreach (var genericHandle in method.GetGenericParameters())
                {
                    owners[genericHandle] = $"generic parameter {reader.GetGenericParameter(genericHandle).Index} of {display}";
                }
            }

            foreach (var fieldHandle in type.GetFields())
            {
                var field = reader.GetFieldDefinition(fieldHandle);
                var name = reader.GetString(field.Name);
                var fieldType = text.FieldDefType(field);
                var (rvaSize, rvaHash) = ReadFieldRva(pe, text, field);
                string? constant = null;
                var defaultValue = field.GetDefaultValue();
                if (!defaultValue.IsNil)
                {
                    var value = reader.GetConstant(defaultValue);
                    if (value.TypeCode == ConstantTypeCode.String)
                    {
                        var blob = reader.GetBlobReader(value.Value);
                        constant = blob.ReadUTF16(blob.Length);
                        Strings.Add(new ScannedString(constant, StringOrigin.Constant));
                    }
                }
                Fields.Add(new FieldRecord(typeName, name, fieldType,
                    typeGenerated || MetadataText.IsGenerated(name), rvaSize, rvaHash, constant));
                owners[fieldHandle] = $"field {typeName}::{name}";
            }

            foreach (var propertyHandle in type.GetProperties())
            {
                owners[propertyHandle] = $"property {typeName}::{reader.GetString(reader.GetPropertyDefinition(propertyHandle).Name)}";
            }
            foreach (var eventHandle in type.GetEvents())
            {
                owners[eventHandle] = $"event {typeName}::{reader.GetString(reader.GetEventDefinition(eventHandle).Name)}";
            }
            foreach (var genericHandle in type.GetGenericParameters())
            {
                owners[genericHandle] = $"generic parameter {reader.GetGenericParameter(genericHandle).Index} of {typeName}";
            }
            foreach (var interfaceHandle in type.GetInterfaceImplementations())
            {
                owners[interfaceHandle] = $"interface implementation on {typeName}";
            }
            firstType = false;
        }
        return owners;
    }

    private static (int Size, string? Hash) ReadFieldRva(PEReader pe, MetadataText text, FieldDefinition field)
    {
        var rva = field.GetRelativeVirtualAddress();
        if (rva == 0) return (0, null);
        var size = FieldDataSize(text, field);
        if (size <= 0) return (0, null);
        if (size > FieldRvaHashLimit) throw new BadImageFormatException("FieldRVA data is implausibly large");
        var block = pe.GetSectionData(rva);
        if (block.Length < size) throw new BadImageFormatException("FieldRVA data runs past its section");
        return (size, Text.Sha256(block.GetContent(0, size).AsSpan()));
    }

    private static int FieldDataSize(MetadataText text, FieldDefinition field)
    {
        var blob = text.Blob(field.Signature);
        var header = blob.ReadSignatureHeader();
        if (header.Kind != SignatureKind.Field) return 0;
        var code = blob.ReadSignatureTypeCode();
        while (code is SignatureTypeCode.RequiredModifier or SignatureTypeCode.OptionalModifier)
        {
            blob.ReadTypeHandle();
            code = blob.ReadSignatureTypeCode();
        }
        switch (code)
        {
            case SignatureTypeCode.Boolean or SignatureTypeCode.SByte or SignatureTypeCode.Byte:
                return 1;
            case SignatureTypeCode.Char or SignatureTypeCode.Int16 or SignatureTypeCode.UInt16:
                return 2;
            case SignatureTypeCode.Int32 or SignatureTypeCode.UInt32 or SignatureTypeCode.Single:
                return 4;
            case SignatureTypeCode.Int64 or SignatureTypeCode.UInt64 or SignatureTypeCode.Double:
                return 8;
            case SignatureTypeCode.TypeHandle:
                var handle = blob.ReadTypeHandle();
                if (handle.Kind != HandleKind.TypeDefinition) return 0;
                return text.Reader.GetTypeDefinition((TypeDefinitionHandle)handle).GetLayout().Size;
            default:
                return 0;
        }
    }

    private void ReadUserStrings(MetadataReader reader)
    {
        if (reader.GetHeapSize(HeapIndex.UserString) == 0) return;
        var handle = MetadataTokens.UserStringHandle(0);
        while (true)
        {
            handle = reader.GetNextHandle(handle);
            if (handle.IsNil) break;
            var value = reader.GetUserString(handle);
            if (value.Length == 0) continue;
            UserStrings.Add(value);
            Strings.Add(new ScannedString(value, StringOrigin.UserString));
        }
    }

    private void ReadResources(PEReader pe, MetadataReader reader)
    {
        foreach (var handle in reader.ManifestResources)
        {
            var resource = reader.GetManifestResource(handle);
            var name = reader.GetString(resource.Name);
            if (!resource.Implementation.IsNil)
            {
                var linked = resource.Implementation.Kind switch
                {
                    HandleKind.AssemblyFile => reader.GetString(reader.GetAssemblyFile((AssemblyFileHandle)resource.Implementation).Name),
                    HandleKind.AssemblyReference => "assembly " + reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)resource.Implementation).Name),
                    _ => resource.Implementation.Kind.ToString(),
                };
                Resources.Add(new ResourceRecord(name, null, linked));
                continue;
            }
            var directory = pe.PEHeaders.CorHeader!.ResourcesDirectory;
            if (directory.Size == 0) throw new BadImageFormatException("Embedded resource without a resources directory");
            var section = pe.GetSectionData(directory.RelativeVirtualAddress);
            if (resource.Offset < 0 || resource.Offset + 4 > Math.Min(section.Length, directory.Size))
            {
                throw new BadImageFormatException($"Resource {name} lies outside the resources directory");
            }
            var blob = section.GetReader((int)resource.Offset, directory.Size - (int)resource.Offset);
            var length = blob.ReadInt32();
            if (length < 0 || length > blob.RemainingBytes)
            {
                throw new BadImageFormatException($"Resource {name} has an invalid length");
            }
            Resources.Add(new ResourceRecord(name, blob.ReadBytes(length), null));
        }
    }

    private void ReadAttributes(MetadataText text, Dictionary<EntityHandle, string> owners)
    {
        var reader = text.Reader;
        foreach (var handle in reader.CustomAttributes)
        {
            var attribute = reader.GetCustomAttribute(handle);
            var ctorType = attribute.Constructor.Kind switch
            {
                HandleKind.MethodDefinition => text.TypeDef(reader.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor).GetDeclaringType()),
                HandleKind.MemberReference => text.MemberParent(reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent).Type,
                _ => "?",
            };
            var parent = attribute.Parent.Kind switch
            {
                HandleKind.AssemblyDefinition => "assembly",
                HandleKind.ModuleDefinition => "module",
                _ => owners.TryGetValue(attribute.Parent, out var owner) ? owner : attribute.Parent.Kind.ToString(),
            };
            var value = attribute.Value.IsNil ? [] : reader.GetBlobBytes(attribute.Value);
            Attributes.Add(new AttributeRecord(ctorType, parent, Text.Sha256(value)[..16],
                MetadataText.IsGenerated(parent), attribute.Constructor.Kind == HandleKind.MemberReference));
            foreach (var run in PrintableRuns(value))
            {
                Strings.Add(new ScannedString(run, StringOrigin.AttributeArgument));
            }
        }
    }

    /// <summary>
    /// Attribute arguments are serialized as length-prefixed UTF-8; extracting printable
    /// runs recovers string arguments (URLs, paths) without decoding enum layouts.
    /// </summary>
    private static IEnumerable<string> PrintableRuns(byte[] value)
    {
        var decoded = Encoding.UTF8.GetString(value);
        var sb = new StringBuilder();
        foreach (var c in decoded)
        {
            if (c >= 0x20 && c != 0x7F && c != '�')
            {
                sb.Append(c);
                continue;
            }
            if (sb.Length >= MinAttributeRun) yield return sb.ToString();
            sb.Clear();
        }
        if (sb.Length >= MinAttributeRun) yield return sb.ToString();
    }
}
