#include <hip/hip_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <iostream>

template <typename T>
void type_row(const char* name)
{
    std::cout << name << ",type,,0," << sizeof(T) << "," << alignof(T) << "\n";
}

template <typename T, typename M>
void vector_field_row(const char* type_name, const char* field_name, M* field, const T& object)
{
    const auto base = reinterpret_cast<const std::uint8_t*>(&object);
    const auto addr = reinterpret_cast<const std::uint8_t*>(field);
    std::cout << type_name << ",field," << field_name << ","
              << static_cast<std::size_t>(addr - base) << ","
              << sizeof(M) << "," << alignof(T) << "\n";
}

template <typename T, typename M>
void field_row(const char* type_name, const char* field_name, M T::*member)
{
    T object{};
    const auto base = reinterpret_cast<const std::uint8_t*>(&object);
    const auto field = reinterpret_cast<const std::uint8_t*>(&(object.*member));
    std::cout << type_name << ",field," << field_name << ","
              << static_cast<std::size_t>(field - base) << ","
              << sizeof(object.*member) << "," << alignof(T) << "\n";
}

template <typename T, typename M>
void field_row_array(const char* type_name, const char* field_name, M T::*member)
{
    field_row(type_name, field_name, member);
}

int main()
{
    std::cout << "type,kind,field,offset,size,align\n";

    type_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600");
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "name", &hipDeviceProp_tR0600::name);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "uuid", &hipDeviceProp_tR0600::uuid);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "luid", &hipDeviceProp_tR0600::luid);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "totalGlobalMem", &hipDeviceProp_tR0600::totalGlobalMem);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "sharedMemPerBlock", &hipDeviceProp_tR0600::sharedMemPerBlock);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "regsPerBlock", &hipDeviceProp_tR0600::regsPerBlock);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "warpSize", &hipDeviceProp_tR0600::warpSize);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "maxThreadsPerBlock", &hipDeviceProp_tR0600::maxThreadsPerBlock);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "maxThreadsDim", &hipDeviceProp_tR0600::maxThreadsDim);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "maxGridSize", &hipDeviceProp_tR0600::maxGridSize);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "multiProcessorCount", &hipDeviceProp_tR0600::multiProcessorCount);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "sharedMemPerMultiprocessor", &hipDeviceProp_tR0600::sharedMemPerMultiprocessor);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "regsPerMultiprocessor", &hipDeviceProp_tR0600::regsPerMultiprocessor);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "gcnArchName", &hipDeviceProp_tR0600::gcnArchName);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "maxSharedMemoryPerMultiProcessor", &hipDeviceProp_tR0600::maxSharedMemoryPerMultiProcessor);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "arch", &hipDeviceProp_tR0600::arch);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "hdpMemFlushCntl", &hipDeviceProp_tR0600::hdpMemFlushCntl);
    field_row<hipDeviceProp_tR0600>("hipDeviceProp_tR0600", "asicRevision", &hipDeviceProp_tR0600::asicRevision);

    type_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc");
    field_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc", "type", &hipExternalMemoryHandleDesc::type);
    field_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc", "handle", &hipExternalMemoryHandleDesc::handle);
    field_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc", "size", &hipExternalMemoryHandleDesc::size);
    field_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc", "flags", &hipExternalMemoryHandleDesc::flags);
    field_row<hipExternalMemoryHandleDesc>("hipExternalMemoryHandleDesc", "reserved", &hipExternalMemoryHandleDesc::reserved);

    type_row<hipExternalMemoryBufferDesc>("hipExternalMemoryBufferDesc");
    field_row<hipExternalMemoryBufferDesc>("hipExternalMemoryBufferDesc", "offset", &hipExternalMemoryBufferDesc::offset);
    field_row<hipExternalMemoryBufferDesc>("hipExternalMemoryBufferDesc", "size", &hipExternalMemoryBufferDesc::size);
    field_row<hipExternalMemoryBufferDesc>("hipExternalMemoryBufferDesc", "flags", &hipExternalMemoryBufferDesc::flags);
    field_row<hipExternalMemoryBufferDesc>("hipExternalMemoryBufferDesc", "reserved", &hipExternalMemoryBufferDesc::reserved);

    type_row<hipLaunchParams>("hipLaunchParams");
    field_row<hipLaunchParams>("hipLaunchParams", "func", &hipLaunchParams::func);
    field_row<hipLaunchParams>("hipLaunchParams", "gridDim", &hipLaunchParams::gridDim);
    field_row<hipLaunchParams>("hipLaunchParams", "blockDim", &hipLaunchParams::blockDim);
    field_row<hipLaunchParams>("hipLaunchParams", "args", &hipLaunchParams::args);
    field_row<hipLaunchParams>("hipLaunchParams", "sharedMem", &hipLaunchParams::sharedMem);
    field_row<hipLaunchParams>("hipLaunchParams", "stream", &hipLaunchParams::stream);

    type_row<hipFunctionLaunchParams>("hipFunctionLaunchParams");
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "function", &hipFunctionLaunchParams::function);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "gridDimX", &hipFunctionLaunchParams::gridDimX);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "gridDimY", &hipFunctionLaunchParams::gridDimY);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "gridDimZ", &hipFunctionLaunchParams::gridDimZ);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "blockDimX", &hipFunctionLaunchParams::blockDimX);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "blockDimY", &hipFunctionLaunchParams::blockDimY);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "blockDimZ", &hipFunctionLaunchParams::blockDimZ);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "sharedMemBytes", &hipFunctionLaunchParams::sharedMemBytes);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "hStream", &hipFunctionLaunchParams::hStream);
    field_row<hipFunctionLaunchParams>("hipFunctionLaunchParams", "kernelParams", &hipFunctionLaunchParams::kernelParams);

    type_row<dim3>("dim3");
    field_row<dim3>("dim3", "x", &dim3::x);
    field_row<dim3>("dim3", "y", &dim3::y);
    field_row<dim3>("dim3", "z", &dim3::z);
    type_row<uint3>("uint3");
    uint3 uint3_object{};
    vector_field_row("uint3", "x", &uint3_object.x, uint3_object);
    vector_field_row("uint3", "y", &uint3_object.y, uint3_object);
    vector_field_row("uint3", "z", &uint3_object.z, uint3_object);

    type_row<hipStream_t>("hipStream_t");
    type_row<hipEvent_t>("hipEvent_t");
    type_row<hipFunction_t>("hipFunction_t");
    type_row<hipExternalMemory_t>("hipExternalMemory_t");
    type_row<hipIpcMemHandle_t>("hipIpcMemHandle_t");
    type_row<hipIpcEventHandle_t>("hipIpcEventHandle_t");
    return 0;
}
