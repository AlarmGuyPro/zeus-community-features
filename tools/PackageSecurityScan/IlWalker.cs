// SPDX-License-Identifier: GPL-2.0-or-later
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;

namespace PackageSecurityScan;

/// <summary>
/// A minimal, strict IL decoder. It walks every instruction with correct operand
/// sizes (including <c>switch</c>) and rejects bytes that are not valid opcodes, so a
/// crafted body cannot desynchronise the walk to hide a call. It looks for two things:
/// clock/year comparisons (time bombs) and <c>calli</c> through an unmanaged calling
/// convention.
/// </summary>
internal static class IlWalker
{
    public const int YearWindow = 8;
    public const int MinYear = 2000;
    public const int MaxYear = 2100;

    private static readonly HashSet<ILOpCode> ValidOpCodes = [.. Enum.GetValues<ILOpCode>()];

    private static readonly HashSet<string> DateTypes =
        new(StringComparer.Ordinal) { "System.DateTime", "System.DateTimeOffset", "System.DateOnly" };

    private static readonly HashSet<string> ClockReads =
        new(StringComparer.Ordinal) { "get_Now", "get_UtcNow", "get_Today" };

    public static void Walk(MetadataText text, MethodBodyBlock body, string declaringType, string method,
        AssemblyModel model)
    {
        var reader = body.GetILReader();
        var index = 0;
        var lastYearIndex = int.MinValue / 2;
        var lastYear = 0;
        var years = new SortedSet<int>();
        var readsClock = false;
        var hit = false;
        while (reader.RemainingBytes > 0)
        {
            int value = reader.ReadByte();
            if (value == 0xFE)
            {
                if (reader.RemainingBytes == 0) throw new BadImageFormatException($"Truncated opcode in {method}");
                value = 0xFE00 | reader.ReadByte();
            }
            var opcode = (ILOpCode)value;
            if (!ValidOpCodes.Contains(opcode))
            {
                throw new BadImageFormatException($"Invalid IL opcode 0x{value:X} in {method}");
            }
            switch (opcode)
            {
                case ILOpCode.Ldc_i4:
                    var constant = ReadInt32(ref reader, method);
                    if (constant is >= MinYear and <= MaxYear)
                    {
                        lastYearIndex = index;
                        lastYear = constant;
                        years.Add(constant);
                    }
                    break;
                case ILOpCode.Call:
                case ILOpCode.Callvirt:
                case ILOpCode.Newobj:
                case ILOpCode.Ldftn:
                case ILOpCode.Ldvirtftn:
                    var target = text.ResolveMethodToken(ReadInt32(ref reader, method));
                    if (target is { } called)
                    {
                        var key = $"{called.Type}::{called.Name}";
                        if (!model.CallersByTarget.TryGetValue(key, out var callers))
                        {
                            callers = new HashSet<string>(StringComparer.Ordinal);
                            model.CallersByTarget.Add(key, callers);
                        }
                        callers.Add(declaringType);
                    }
                    if (opcode is ILOpCode.Ldftn or ILOpCode.Ldvirtftn) break;
                    if (target is { } t && DateTypes.Contains(t.Type))
                    {
                        if (ClockReads.Contains(t.Name)) readsClock = true;
                        if (index - lastYearIndex <= YearWindow)
                        {
                            model.TimeBombs.Add($"{method}: year constant {lastYear} feeds {t.Type}::{t.Name}");
                            hit = true;
                        }
                    }
                    break;
                case ILOpCode.Calli:
                    var token = ReadInt32(ref reader, method);
                    if (IsUnmanagedCalli(text, token, out var convention))
                    {
                        model.UnmanagedCalli.Add($"{method}: calli with unmanaged calling convention {convention}");
                    }
                    break;
                case ILOpCode.Switch:
                    var count = (uint)ReadInt32(ref reader, method);
                    if (count > (uint)reader.RemainingBytes / 4)
                    {
                        throw new BadImageFormatException($"Truncated switch table in {method}");
                    }
                    Skip(ref reader, (int)count * 4, method);
                    break;
                default:
                    Skip(ref reader, OperandSize(opcode), method);
                    break;
            }
            index++;
        }
        if (!hit && readsClock && years.Count > 0)
        {
            model.TimeBombs.Add($"{method}: reads the clock and loads year constant(s) {string.Join(", ", years)}");
        }
    }

    private static bool IsUnmanagedCalli(MetadataText text, int token, out SignatureCallingConvention convention)
    {
        convention = SignatureCallingConvention.Default;
        if ((TableIndex)(token >>> 24) != TableIndex.StandAloneSig)
        {
            throw new BadImageFormatException($"calli operand 0x{token:X8} is not a signature token");
        }
        var row = token & 0xFFFFFF;
        text.CheckRow(TableIndex.StandAloneSig, row, token);
        var signature = text.Reader.GetStandaloneSignature(MetadataTokens.StandaloneSignatureHandle(row));
        var blob = text.Blob(signature.Signature);
        convention = blob.ReadSignatureHeader().CallingConvention;
        return convention is not (SignatureCallingConvention.Default or SignatureCallingConvention.VarArgs);
    }

    private static int ReadInt32(ref BlobReader reader, string method)
    {
        if (reader.RemainingBytes < 4) throw new BadImageFormatException($"Truncated operand in {method}");
        return reader.ReadInt32();
    }

    private static void Skip(ref BlobReader reader, int bytes, string method)
    {
        if (bytes == 0) return;
        if (reader.RemainingBytes < bytes) throw new BadImageFormatException($"Truncated operand in {method}");
        reader.Offset += bytes;
    }

    private static int OperandSize(ILOpCode opcode)
    {
        if (opcode.IsBranch()) return opcode.GetBranchOperandSize();
        return opcode switch
        {
            ILOpCode.Ldarg_s or ILOpCode.Ldarga_s or ILOpCode.Starg_s or ILOpCode.Ldloc_s or
                ILOpCode.Ldloca_s or ILOpCode.Stloc_s or ILOpCode.Ldc_i4_s or ILOpCode.Unaligned => 1,
            ILOpCode.Ldarg or ILOpCode.Ldarga or ILOpCode.Starg or ILOpCode.Ldloc or
                ILOpCode.Ldloca or ILOpCode.Stloc => 2,
            ILOpCode.Ldc_i4 or ILOpCode.Ldc_r4 => 4,
            ILOpCode.Ldc_i8 or ILOpCode.Ldc_r8 => 8,
            ILOpCode.Jmp or ILOpCode.Call or ILOpCode.Calli or ILOpCode.Callvirt or ILOpCode.Cpobj or
                ILOpCode.Ldobj or ILOpCode.Ldstr or ILOpCode.Newobj or ILOpCode.Castclass or
                ILOpCode.Isinst or ILOpCode.Unbox or ILOpCode.Ldfld or ILOpCode.Ldflda or
                ILOpCode.Stfld or ILOpCode.Ldsfld or ILOpCode.Ldsflda or ILOpCode.Stsfld or
                ILOpCode.Stobj or ILOpCode.Box or ILOpCode.Newarr or ILOpCode.Ldelema or
                ILOpCode.Ldelem or ILOpCode.Stelem or ILOpCode.Unbox_any or ILOpCode.Refanyval or
                ILOpCode.Mkrefany or ILOpCode.Ldtoken or ILOpCode.Ldftn or ILOpCode.Ldvirtftn or
                ILOpCode.Initobj or ILOpCode.Constrained or ILOpCode.Sizeof => 4,
            _ => 0,
        };
    }
}
