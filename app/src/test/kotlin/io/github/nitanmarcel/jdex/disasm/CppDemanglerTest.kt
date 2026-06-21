package io.github.nitanmarcel.jdex.disasm

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class CppDemanglerTest {
    private fun check(mangled: String, expected: String) = assertEquals(expected, CppDemangler.demangle(mangled), mangled)

    @Test fun freeFunction() = check("_Z3fooidPKc", "foo(int, double, char const*)")
    @Test fun ctor() = check("_ZN3FooC1Ev", "Foo::Foo()")
    @Test fun dtor() = check("_ZNSt11logic_errorD0Ev", "std::logic_error::~logic_error()")
    @Test fun ctorWithArg() = check("_ZNSt11logic_errorC1EPKc", "std::logic_error::logic_error(char const*)")
    @Test fun operatorDelete() = check("_ZdlPv", "operator delete(void*)")
    @Test fun operatorDeleteNothrow() = check("_ZdlPvRKSt9nothrow_t", "operator delete(void*, std::nothrow_t const&)")
    @Test fun substitution() = check("_ZN3Foo3barENS_3BazE", "Foo::bar(Foo::Baz)")
    @Test fun constMethod() = check("_ZNKSt11__timepunctIcE15_M_am_pm_formatEPKc", "std::__timepunct<char>::_M_am_pm_format(char const*) const")
    @Test fun multiArgConstMethod() = check("_ZNKSt11__timepunctIcE6_M_putEPcjPKcPK2tm", "std::__timepunct<char>::_M_put(char*, unsigned int, char const*, tm const*) const")
    @Test fun nestedTemplate() = check("_ZNKSt6vectorIiSaIiEE4sizeEv", "std::vector<int, std::allocator<int>>::size() const")
    @Test fun templateFunctionWithReturn() = check("_Z3maxIiET_S0_S0_", "int max<int>(int, int)")
    @Test fun refQualifiedConstMethod() = check("_ZNKRSt7__cxx1115basic_stringbufIcSt11char_traitsIcESaIcEE3strEv", "std::__cxx11::basic_stringbuf<char, std::char_traits<char>, std::allocator<char>>::str() const &")
    @Test fun boolLiteralTemplateArg() = check("_ZN9__gnu_cxx6__poolILb1EE10_M_destroyEv", "__gnu_cxx::__pool<true>::_M_destroy()")
    @Test fun unsignedLongLiteralTemplateArg() = check("_ZNSt5arrayIiLm5EE4sizeEv", "std::array<int, 5ul>::size()")
    @Test fun intLiteralTemplateArg() = check("_Z3addILi3EEiv", "int add<3>()")
    @Test fun unsignedIntLiteralTemplateArg() = check("_Z3fooILj4EEvv", "void foo<4u>()")
    @Test fun nestedFunctionPointerReturn() = check("_Z1hPFPFvvEvE", "h(void (*(*)())())")
    @Test fun nestedFunctionPointerReturnWithArg() = check("_Z1fPFPFviEvE", "f(void (*(*)())(int))")
    @Test fun directTemplateParameterPack() = check("_Z3barIJifdEEvDpT_", "void bar<int, float, double>(int, float, double)")
    @Test fun vtable() = check("_ZTVSt13runtime_error", "vtable for std::runtime_error")
    @Test fun typeinfo() = check("_ZTISt13runtime_error", "typeinfo for std::runtime_error")
    @Test fun guardVariable() = check("_ZGVNSt7collateIcE2idE", "guard variable for std::collate<char>::id")
    @Test fun dataMember() = check("_ZNSt7collateIcE2idE", "std::collate<char>::id")

    @Test fun stdAbbrevTemplateIdSubstitution() =
        check("_ZNSaIcEC1ERKS_", "std::allocator<char>::allocator(std::allocator<char> const&)")

    @Test fun basicStringAbbrevBackref() =
        check(
            "_ZNKSbIwSt11char_traitsIwESaIwEE7compareERKS2_",
            "std::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t>>::compare(std::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t>> const&) const",
        )

    @Test fun constMemberFunctionTemplateReturnType() =
        check("_ZNK1C4convIiEET_S1_", "int C::conv<int>(int) const")

    @Test fun stdAbbrevNotSubstitutableInNestedName() =
        check("_ZNSs13_S_copy_charsEPcPKcS1_", "std::string::_S_copy_chars(char*, char const*, char const*)")

    @Test fun stdAbbrevNotSubstitutableAsType() =
        check(
            "_ZNSs7replaceEN9__gnu_cxx17__normal_iteratorIPcSsEES2_RKSs",
            "std::string::replace(__gnu_cxx::__normal_iterator<char*, std::string>, __gnu_cxx::__normal_iterator<char*, std::string>, std::string const&)",
        )

    @Test fun cvQualifiedPointerToMemberFunction() =
        check("_Z3mfnMN3ns13ns25DerivEiMS1_KFiiE", "mfn(int ns1::ns2::Deriv::*, int (ns1::ns2::Deriv::*)(int) const)")

    @Test fun functionTemplateIdNotSubstitutable() =
        check(
            "_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_",
            "std::basic_ostream<char, std::char_traits<char>>& std::endl<char, std::char_traits<char>>(std::basic_ostream<char, std::char_traits<char>>&)",
        )

    @Test fun rejectsNonMangled() {
        assertNull(CppDemangler.demangle("foo"))
        assertNull(CppDemangler.demangle("sub_1234"))
        assertNull(CppDemangler.demangle("Java_com_example_Native_compute"))
        assertNull(CppDemangler.demangle(""))
    }

    @Test fun rejectsMalformedTrailingGarbage() {
        assertNull(CppDemangler.demangle("_ZN3FooC1Ev_EXTRA"))
    }
}
