// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Text;
using System.Reflection;
using System.Reflection.Emit;
using Xunit;

namespace System.Reflection.Emit.Tests
{
    public class Test
    {
        private int _test = 0;
        private int _ii_Test = 0;
        protected Test()
        {
        }
        protected Test(int j)
        {
            _test = j;
        }
        protected Test(int j, int k)
        {
            _test = j;
            _ii_Test = k;
        }
    }

    public class TypeBuilderGetElementType
    {
        [Fact]
        public void TestThrowsExceptionForNotSupported1()
        {
            TypeBuilder myBuilder = CreateMyTypeBuilder();
            Assert.Throws<NotSupportedException>(() => { myBuilder.GetElementType(); });
        }

        [Fact]
        public void TestThrowsExceptionForNotSupported2()
        {
            AssemblyName myAsmName =
                new AssemblyName("TypeBuilderGetFieldExample");
            AssemblyBuilder myAssembly = AssemblyBuilder.DefineDynamicAssembly(
                myAsmName, AssemblyBuilderAccess.Run);
            ModuleBuilder myModule = TestLibrary.Utilities.GetModuleBuilder(myAssembly, "Module1");

            TypeBuilder myType = myModule.DefineType("Test",
                TypeAttributes.Class | TypeAttributes.Public);

            Assert.Throws<NotSupportedException>(() => { myType.GetElementType(); });
        }

        public TypeBuilder CreateMyTypeBuilder()
        {
            AssemblyName myAsmName =
                new AssemblyName("TypeBuilderGetFieldExample");
            AssemblyBuilder myAssembly = AssemblyBuilder.DefineDynamicAssembly(
                myAsmName, AssemblyBuilderAccess.Run);
            ModuleBuilder myModule = TestLibrary.Utilities.GetModuleBuilder(myAssembly, "Module1");

            TypeBuilder myType = myModule.DefineType("Sample",
                TypeAttributes.Class | TypeAttributes.Public);

            string[] typeParamNames = { "T" };
            GenericTypeParameterBuilder[] typeParams =
                myType.DefineGenericParameters(typeParamNames);

            ConstructorBuilder ctor = myType.DefineDefaultConstructor(
                MethodAttributes.PrivateScope | MethodAttributes.Public |
                MethodAttributes.HideBySig | MethodAttributes.SpecialName |
                MethodAttributes.RTSpecialName);

            FieldBuilder myField = myType.DefineField("Field",
                typeParams[0].AsType(),
                FieldAttributes.Public);

            MethodBuilder genMethod = myType.DefineMethod("GM",
                MethodAttributes.Public | MethodAttributes.Static);
            string[] methodParamNames = { "U" };
            GenericTypeParameterBuilder[] methodParams =
                genMethod.DefineGenericParameters(methodParamNames);

            genMethod.SetSignature(null, null, null,
                new Type[] { methodParams[0].AsType() }, null, null);

            ILGenerator ilg = genMethod.GetILGenerator();

            Type SampleOfU = myType.MakeGenericType(methodParams[0].AsType());

            ilg.DeclareLocal(SampleOfU);

            ConstructorInfo ctorOfU = TypeBuilder.GetConstructor(
                SampleOfU, ctor);
            ilg.Emit(OpCodes.Newobj, ctorOfU);

            ilg.Emit(OpCodes.Stloc_0);
            ilg.Emit(OpCodes.Ldloc_0);
            ilg.Emit(OpCodes.Ldarg_0);

            FieldInfo FieldOfU = TypeBuilder.GetField(
                SampleOfU, myField);

            ilg.Emit(OpCodes.Stfld, FieldOfU);

            ilg.Emit(OpCodes.Ldloc_0);
            ilg.Emit(OpCodes.Ldfld, FieldOfU);
            ilg.Emit(OpCodes.Box, methodParams[0].AsType());
            MethodInfo writeLineObj =
                typeof(Console).GetMethod("WriteLine",
                    new Type[] { typeof(object) });
            ilg.EmitCall(OpCodes.Call, writeLineObj, null);
            ilg.Emit(OpCodes.Ret);

            TypeBuilder dummy = myModule.DefineType("Dummy",
                TypeAttributes.Class | TypeAttributes.NotPublic);
            MethodBuilder entryPoint = dummy.DefineMethod("Main",
                MethodAttributes.Public | MethodAttributes.Static,
                null, null);
            ilg = entryPoint.GetILGenerator();

            Type SampleOfInt =
                myType.MakeGenericType(typeof(int));

            MethodInfo SampleOfIntGM = TypeBuilder.GetMethod(SampleOfInt,
                genMethod);

            MethodInfo GMOfString =
                SampleOfIntGM.MakeGenericMethod(typeof(string));

            ilg.Emit(OpCodes.Ldstr, "Hello, world!");
            ilg.EmitCall(OpCodes.Call, GMOfString, null);
            ilg.Emit(OpCodes.Ret);

            myType.CreateTypeInfo().AsType();

            return myType;
        }
    }
}
