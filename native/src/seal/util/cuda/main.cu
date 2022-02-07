#include "iostream"
#include "main.cuh"
__global__ void cuda_hello(){
    printf("Hello World from GPU!\n");
}

__host__ void haha(uint32_t a, uint32_t b)
{
    cuda_hello<<<1,1>>>();
    {
        cudaError_t cudaerr = cudaDeviceSynchronize();
        if (cudaerr != cudaSuccess)
            printf("kernel launch failed with error \"%s\".\n",
                   cudaGetErrorString(cudaerr));
    }
}