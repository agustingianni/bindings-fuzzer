#pragma once

#include <string>
#include <vector>
#include <cstddef>
#include <memory>
#include <ruby/ruby.h>

#include "abstract-fuzzer.h"

namespace Ruby
{
    struct TargetFunction
    {
        std::vector<DataType> m_arguments;

        VALUE obj;
        ID method_id;
        int nargs;
        std::vector<VALUE> args;

        // TODO(goose): we are assuming all target functions are part of a class.
        // Use a qualifier class or something more generic to describe things to fuzz.
        TargetFunction(const std::string &module, const std::string &cls, const std::string &name, std::vector<DataType> arguments);
    };

    namespace Utilities
    {
        VALUE debug(VALUE v);
        VALUE eval(const std::string &code, bool debug = false);
        VALUE call_protected(TargetFunction &function, bool debug = false);
    }

    class Fuzzer final : public AbstractFuzzer
    {
    public:
        static std::unique_ptr<Fuzzer> create();

        void fuzz(const uint8_t *data, size_t size) override;

        void addTargetFunction(const TargetFunction &target)
        {
            m_target.push_back(target);
        }

    private:
        Fuzzer();
        std::vector<TargetFunction> m_target;
    };
}