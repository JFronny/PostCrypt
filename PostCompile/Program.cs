extern alias mc1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using BrokenEvent.ILStrip;
using mc1::ILRepacking;
using Mono.Cecil;
using Mono.Cecil.Cil;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using ParameterAttributes = Mono.Cecil.ParameterAttributes;
using TypeAttributes = Mono.Cecil.TypeAttributes;

namespace PostCompile
{
    extern alias mc1;

    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Assembly:");
                Console.Write("> ");
                args = new[] {Console.ReadLine()};
            }
            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Invalid path");
                return;
            }
            byte[] assemblyData = GetOptimizedBytes(args[0]);
            byte[] encryptedData = Encrypt(assemblyData, out byte[] key);
            string baseKey = Base64(key);
            //Environment.CurrentDirectory = cd;
            AssemblyDefinition def = GenerateBuilder(encryptedData, baseKey, BitConverter.ToInt32(key.Take(4).ToArray(), 0), AssemblyDefinition.ReadAssembly(args[0]).MainModule.Kind);
            string outFile = $"{Path.GetFileNameWithoutExtension(args[0])}.builder{Path.GetExtension(args[0])}";
            def.Write(outFile);
            File.WriteAllText("key.txt", baseKey);
            File.WriteAllText("data.txt", $"{string.Join("\n", encryptedData.Select(s => $"cancer.Add({s});"))}");
            
            Console.WriteLine("Testing crypto");
            CopyClass.Decrypt(encryptedData, Convert.FromBase64String(baseKey));
            
            if (args.Length > 1 && args[1].Trim("-\\/".ToCharArray()).ToLower() == "run")
            {
                Console.WriteLine("Handing control to app");
                Console.WriteLine("--------------------------");
                Console.WriteLine();
                Assembly.LoadFrom(outFile).EntryPoint.Invoke(null, args.Length > 2 ? new object[] {args.Skip(2).ToArray()} : new object[] {null});
                Console.WriteLine();
                Console.WriteLine("--------------------------");
                Console.WriteLine("[SUCCESS] Program finished");
                Console.WriteLine("--------------------------");
            }
        }

        private static MethodDefinition CopyMethod(Delegate name, TypeDefinition targetType)
        {
            string cd = Environment.CurrentDirectory;
            Environment.CurrentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            AssemblyDefinition def = AssemblyDefinition.ReadAssembly(typeof(Program).Assembly.Location);
            
            MethodReference source = def.MainModule.Import(name.Method);
            
            MethodDefinition sourceMethod = source.Resolve();
            MethodDefinition targetMethod = new MethodDefinition(name.Method.Name, sourceMethod.Attributes, def.MainModule.Import(source.ReturnType));
            ILProcessor sourceIL = sourceMethod.Body.GetILProcessor();

            foreach (Instruction i in sourceMethod.Body.Instructions.ToList())
            {
                Instruction ci = i;
                if (i.Operand is MethodReference mref)
                    ci = sourceIL.Create(i.OpCode, mref.Name == "Decrypt" ? targetType.Module.Import(targetType.Methods.First(s => s.Name == mref.Name)) : targetType.Module.Import(mref));
                else if (i.Operand is TypeReference tref) ci = sourceIL.Create(i.OpCode, targetType.Module.Import(tref));
                else if (i.Operand is FieldReference fref)
                    ci = sourceIL.Create(i.OpCode, targetType.Module.Import(fref));
                else if (i.Operand is TypeDefinition tdef)
                    ci = sourceIL.Create(i.OpCode, targetType.Module.Import(tdef));
                if (ci != i) sourceIL.Replace(i, ci);
            }
            targetMethod.Body = sourceMethod.Body;

            foreach (VariableDefinition v in sourceMethod.Body.Variables.ToArray()) v.VariableType = targetType.Module.Import(v.VariableType);

            targetMethod.Parameters.Clear();
            foreach (ParameterDefinition p in sourceMethod.Parameters)
            {
                ParameterDefinition np = new ParameterDefinition(p.Name, p.Attributes, targetType.Module.Import(p.ParameterType));
                targetMethod.Parameters.Add(np);
            }

            targetMethod.Body.InitLocals = true;
            
            targetType.Methods.Add(targetMethod);
            Environment.CurrentDirectory = cd;
            return targetMethod;
        }

        private static AssemblyDefinition GenerateBuilder(byte[] encryptedData, string key, int rndStart, ModuleKind kind)
        {
            Random rnd = new Random(rndStart);
            string progName = rnd.GenerateRandomString();
            AssemblyDefinition definition = AssemblyDefinition.CreateAssembly(new AssemblyNameDefinition(progName, new Version(1, 0, 0, 0)), progName, kind);
            ModuleDefinition module = definition.MainModule;
            TypeDefinition programType = new TypeDefinition(progName, "Program", TypeAttributes.Class | TypeAttributes.Public, module.TypeSystem.Object);

            module.Types.Add(programType);
            
            MethodDefinition ctor = new MethodDefinition(".ctor", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, module.TypeSystem.Void);

            ILProcessor il = ctor.Body.GetILProcessor();
            
            il.Append(il.Create(OpCodes.Ldarg_0));
            
            il.Append(il.Create(OpCodes.Call, module.Import(typeof(object).GetConstructor(Array.Empty<Type>()))));
            
            il.Append(il.Create(OpCodes.Nop));
            il.Append(il.Create(OpCodes.Ret));
            
            programType.Methods.Add(ctor);
            
            CopyMethod((Func<byte[], byte[], byte[]>)CopyClass.Decrypt, programType);
            MethodDefinition run = CopyMethod((Action<byte[], string, string[]>)CopyClass.Run, programType);
            
            MethodDefinition mainMethod = new MethodDefinition("Main",
                MethodAttributes.Public | MethodAttributes.Static, module.TypeSystem.Void);

            programType.Methods.Add(mainMethod);

            ParameterDefinition argsParameter = new ParameterDefinition("args",
                ParameterAttributes.None, module.Import(typeof(string[])));

            mainMethod.Parameters.Add(argsParameter);
            mainMethod.Body.Variables.Add(new VariableDefinition(rnd.GenerateRandomString(), module.Import(typeof(List<byte>))));

            il = mainMethod.Body.GetILProcessor();

            il.Append(il.Create(OpCodes.Nop));
            
            il.Append(il.Create(OpCodes.Newobj, module.Import(typeof(List<byte>).GetConstructor(new Type[0]))));
            il.Append(il.Create(OpCodes.Stloc_0));
            
            for (int i = 0; i < encryptedData.Length; i++)
            {
                il.Emit(OpCodes.Ldloc_0);
                byte tmp = encryptedData[i];
                if (tmp >= -128 && tmp <= 127)
                    il.Emit(OpCodes.Ldc_I4_S, (sbyte)tmp);
                else
                    il.Emit(OpCodes.Ldc_I4, (int)tmp);
                il.Emit(OpCodes.Callvirt, module.Import(typeof(List<byte>).GetMethod("Add")));
                il.Emit(OpCodes.Nop);
            }
            
            il.Emit(OpCodes.Ldloc_0);
            il.Emit(OpCodes.Callvirt, module.Import(typeof(List<byte>).GetMethod("ToArray")));
            il.Emit(OpCodes.Ldstr, key);
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, module.Import(run));

            il.Append(il.Create(OpCodes.Nop));
            il.Append(il.Create(OpCodes.Ret));

            definition.EntryPoint = mainMethod;

            return definition;
        }

        private static string GenerateRandomString(this Random rnd)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            return new string(Enumerable.Repeat(chars, 12).Select(s => s[rnd.Next(s.Length)]).ToArray());
        }

        private static byte[] GetOptimizedBytes(string path)
        {
            Environment.CurrentDirectory = Path.GetDirectoryName(path) ?? throw new ArgumentException("Path not found");
            string asmNameExt = Path.GetFileName(path);
            string asmName = Path.GetFileNameWithoutExtension(asmNameExt);
            string asmNameMerged = $"{asmName}.merged{Path.GetExtension(asmNameExt)}";
            string asmNameMinified = $"{asmName}.minified{Path.GetExtension(asmNameExt)}";
            Assembly asm = Assembly.LoadFrom(path);
            ILRepack repack = new ILRepack(new RepackOptions(new[]{"/internalize", $"/out:{asmNameMerged}", asmNameExt}.Concat(GetDependentFilesPass(asm, Environment.CurrentDirectory))));
            repack.Repack();
            ILStrip optimizer = new ILStrip(asmNameMerged);
            optimizer.MakeInternal();
            optimizer.ScanUsedClasses();
            optimizer.ScanUnusedClasses();
            optimizer.CleanupUnusedClasses();
            optimizer.CleanupUnusedResources();
            optimizer.CleanupUnusedReferences();
            optimizer.Save(asmNameMinified);
            optimizer.Dispose();
            File.Delete(asmNameMerged);
            byte[] result = File.ReadAllBytes(asmNameMinified);
            File.Delete(asmNameMinified);
            return result;
        }

        private static string Base64(byte[] data) => Convert.ToBase64String(data);

        private static byte[] Encrypt(byte[] data, out byte[] key)
        {
            key = Hash(data);
            if (key is null)
                throw new ArgumentException("Key must have valid value.", nameof(key));
            if (data is null)
                throw new ArgumentException("The text must have valid value.", nameof(data));

            byte[] buffer = data;
            SHA512CryptoServiceProvider hash = new SHA512CryptoServiceProvider();
            byte[] aesKey = new byte[24];
            Buffer.BlockCopy(hash.ComputeHash(key), 0, aesKey, 0, 24);

            using Aes aes = Aes.Create();
            if (aes == null)
                throw new ArgumentException("Parameter must not be null.", nameof(aes));

            aes.Key = aesKey;

            using ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using MemoryStream resultStream = new MemoryStream();
            using (CryptoStream aesStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
            {
                using MemoryStream plainStream = new MemoryStream(buffer);
                plainStream.CopyTo(aesStream);
            }

            byte[] result = resultStream.ToArray();
            byte[] combined = new byte[aes.IV.Length + result.Length];
            Array.ConstrainedCopy(aes.IV, 0, combined, 0, aes.IV.Length);
            Array.ConstrainedCopy(result, 0, combined, aes.IV.Length, result.Length);
            return combined;
        }

        private static byte[] Hash(byte[] data)
        {
            using MD5 sec = new MD5CryptoServiceProvider();
            return sec.ComputeHash(data).ToArray();
        }
        
        private static string[] GetDependentFilesPass(Assembly assembly, string poe)
        {
            return CollectDeps(assembly, poe).Select(s => Path.GetFullPath($"{s.Name}.dll")).Where(File.Exists)
                .ToArray();
        }

        private static AssemblyName[] CollectDeps(Assembly assembly, string poe)
        {
            List<AssemblyName> tmp = assembly.GetReferencedAssemblies().ToList();
            int i = 0;
            while (i < tmp.Count())
            {
                Assembly tmp1 = Assembly.Load(tmp[i]);
                tmp.AddRange(tmp1.GetReferencedAssemblies().Where(s => Path.GetFullPath(s.Name).StartsWith(poe) && !tmp.Any(a => a.Name == s.Name)));
                i++;
            }
            return tmp.ToArray();
        }
    }
}