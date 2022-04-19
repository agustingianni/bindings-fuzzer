#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

enum class DataType
{
    CString
};

struct CString
{
    const char *m_data;
    size_t m_size;

    CString(const char *data, size_t size)
        : m_data(data), m_size(size)
    {
    }
};

class FuzzingDataProvider
{
public:
    void feed(const uint8_t *data, size_t size)
    {
        m_data = data;
        m_size = size;
        m_off = 0;
    }

    bool empty() const
    {
        return !capacity();
    }

    size_t capacity() const
    {
        return m_size - m_off;
    }

    template <typename DataType>
    std::optional<DataType> consume(size_t hint = 0)
    {
        if (empty() || capacity() < sizeof(DataType))
            return {};

        auto ret = *data<DataType>();
        m_off += sizeof(DataType);

        return ret;
    }

private:
    // TODO(goose): limit the types we can use here.
    template <typename DataType>
    DataType *data()
    {
        return (DataType *)(&m_data[m_off]);
    }

    const uint8_t *m_data{nullptr};
    size_t m_size{0};
    size_t m_off{0};
};

class AbstractFuzzer
{
public:
    virtual void fuzz(const uint8_t *data, size_t size) = 0;

protected:
    FuzzingDataProvider m_data_provider;
    bool m_debug{false};
};
