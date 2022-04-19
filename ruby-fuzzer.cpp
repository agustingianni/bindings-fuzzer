#include <numeric>
#include <string>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <ruby/ruby.h>

#include "abstract-fuzzer.h"
#include "ruby-fuzzer.h"

namespace Ruby::Utilities
{
    VALUE
    debug(VALUE v)
    {
        ID sym_puts = rb_intern("puts");
        ID sym_inspect = rb_intern("inspect");
        VALUE out = rb_funcall(v, sym_inspect, 0);
        rb_funcall(rb_mKernel, sym_puts, 1, out);
        return out;
    }

    VALUE
    eval(const std::string &code, bool debug)
    {
        int state = 0;
        VALUE result = rb_eval_string_protect(code.c_str(), &state);
        if (state != 0)
        {
            if (debug)
                Utilities::debug(rb_errinfo());

            rb_set_errinfo(Qnil);
        }

        return result;
    }

    static VALUE
    protected_call(VALUE rdata)
    {
        auto &data = *reinterpret_cast<struct Ruby::TargetFunction *>(rdata);
        return rb_funcall2(data.obj, data.method_id, data.nargs, data.args.data());
    };

    VALUE
    call_protected(TargetFunction &function, bool debug)
    {
        int state = 0;
        VALUE result = rb_protect(protected_call, reinterpret_cast<VALUE>(&function), &state);
        if (state != 0)
        {
            if (debug)
                Utilities::debug(rb_errinfo());

            rb_set_errinfo(Qnil);
        }

        return result;
    }

    VALUE
    require(const std::string &module)
    {
        return eval("require '" + module + "'\n");
    }
} // namespace Ruby::Utilities

namespace Ruby
{
    TargetFunction::TargetFunction(const std::string &module, const std::string &cls, const std::string &name, std::vector<DataType> arguments)
        : m_arguments(std::move(arguments))
    {
        // Import the required module.
        Utilities::require(module.c_str());

        // Resolve the target function.
        obj = rb_path2class(cls.c_str());
        method_id = rb_intern(name.c_str());
        nargs = static_cast<int>(m_arguments.size());
        args.resize(m_arguments.size());
    }

    Fuzzer::Fuzzer() : AbstractFuzzer()
    {
        RUBY_INIT_STACK;
        ruby_init();
        ruby_init_loadpath();
    }

    static std::optional<VALUE> get_fuzzed_value(FuzzingDataProvider &data_provider, const std::vector<DataType> &arguments, int i)
    {
        if (!data_provider.capacity())
            return {};

        // Count how many variable size data types we have.
        auto variable_types_count = std::count(arguments.begin(), arguments.end(), DataType::CString);

        switch (arguments[i])
        {
        case DataType::CString:
        {
            // Calculate the size of the string based on the amount of variable sized types.
            auto string_size = data_provider.capacity() / variable_types_count;

            // Generate a CString.
            if (auto opt_data = data_provider.consume<CString>(string_size); opt_data)
                return rb_str_new(opt_data.value().m_data, opt_data.value().m_size);
        }
        break;

        default:
            break;
        }

        return {};
    }

    void Fuzzer::fuzz(const uint8_t *data, size_t size)
    {
        m_data_provider.feed(data, size);

        for (auto target : m_target)
        {
            for (auto i = 0; i < target.m_arguments.size(); i++)
            {
                auto opt_value = get_fuzzed_value(m_data_provider, target.m_arguments, i);
                if (!opt_value)
                    return;

                target.args[i] = opt_value.value();
            }

            Ruby::Utilities::call_protected(target);
        }
    }

    std::unique_ptr<Fuzzer> Fuzzer::create()
    {
        auto fuzzer = std::unique_ptr<Fuzzer>(new Fuzzer());

        // fuzzer->addTargetFunction({"date", "Date", "strptime", {DataType::CString, DataType::CString}});
        // fuzzer->addTargetFunction({"date", "Date", "httpdate", {DataType::CString}});
        // fuzzer->addTargetFunction({"json", "JSON", "parse", {DataType::CString}});
        // fuzzer->addTargetFunction({"psych", "Psych", "parse", {DataType::CString}});
        // fuzzer->addTargetFunction({"openssl", "OpenSSL::PKey", "read", {DataType::CString}});
        // fuzzer->addTargetFunction({"openssl", "OpenSSL::PKCS7", "read_smime", {DataType::CString}});
        // fuzzer->addTargetFunction({"openssl", "Kernel", "sprintf", {DataType::CString, DataType::CString}});
        // fuzzer->addTargetFunction({"date", "Date", "parse", {DataType::CString}});
        fuzzer->addTargetFunction({"CGI", "CGI", "unescapeHTML", {DataType::CString}});

        return fuzzer;
    }

} // namespace Ruby

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static auto fuzzer = Ruby::Fuzzer::create();
    fuzzer->fuzz(data, size);

    // std::string code;
    // code.append("require 'openssl'\n");
    // code.append("OpenSSL::PKey.read('AAAAAAAAAAAAAAAAAAAA')\n");
    // Ruby::Utilities::eval(code, true);
    // exit(1);

    return 0;
}
