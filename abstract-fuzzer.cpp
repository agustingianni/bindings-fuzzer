#include "abstract-fuzzer.h"

template <>
std::optional<CString> FuzzingDataProvider::consume(size_t hint)
{
    auto actual_size = hint ?: capacity();
    if (empty() || capacity() < actual_size)
        return {};

    auto ret = CString(data<const char>(), actual_size);
    m_off += actual_size;

    return ret;
}
