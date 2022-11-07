#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

#include <stdint.h>

typedef int32_t fp_float;

#define FLOAT_BITS 14

#define FP_FROM_INT(A) ((fp_float)(A << FLOAT_BITS))
#define FP_ADD(A, B) (A + B)
#define FP_ADD_INT(A, B) (A + (B << FLOAT_BITS))
#define FP_SUB(A, B) (A - B)
#define FP_SUB_INT(A, B) (A - (B << FLOAT_BITS))
#define FP_DIV(A, B) ((fp_float)((((int64_t) A) << FLOAT_BITS) / B))
#define FP_DIV_INT(A, B) (A / B)
#define FP_MUL(A, B) ((fp_float)(((int64_t) A) * B >> FLOAT_BITS))
#define FP_MUL_INT(A, B) (A * B)
#define FP_ROUND(A) (FP_ROUND_BITS(A, FLOAT_BITS))
#define FP_ROUND_BITS(A, BITS) (A >= 0 ? ((A + (1 << (BITS - 1))) >> BITS) : ((A - (1 << (BITS - 1))) >> BITS))
#define FP_INT_PART(A) (A >> FLOAT_BITS)

#endif /**< threads/fixed_point.h */