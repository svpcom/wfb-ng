#ifndef __ZFEX_PP_H
#define __ZFEX_PP_H

/**
 * zfex -- fast forward error correction library with Python interface
 *
 * Copyright (C) 2022 Wojciech Migda
 *
 * This file is part of zfex.
 *
 * See README.rst for licensing information.
 */

#ifdef __cplusplus
extern "C"
{
#endif


#define PP_EXPAND(...) __VA_ARGS__

#define PP_REPEAT_2(ss) ss(0) ss(1)

/*
 * generated with
 *
 * for i in `seq 2 63` ; do echo \#define PP_REPEAT_$(($i + 1))\(ss\) PP_REPEAT_$i\(ss\) ss\($i\) ; done
 *
 */
#define PP_REPEAT_3(ss) PP_REPEAT_2(ss) ss(2)
#define PP_REPEAT_4(ss) PP_REPEAT_3(ss) ss(3)
#define PP_REPEAT_5(ss) PP_REPEAT_4(ss) ss(4)
#define PP_REPEAT_6(ss) PP_REPEAT_5(ss) ss(5)
#define PP_REPEAT_7(ss) PP_REPEAT_6(ss) ss(6)
#define PP_REPEAT_8(ss) PP_REPEAT_7(ss) ss(7)
#define PP_REPEAT_9(ss) PP_REPEAT_8(ss) ss(8)
#define PP_REPEAT_10(ss) PP_REPEAT_9(ss) ss(9)
#define PP_REPEAT_11(ss) PP_REPEAT_10(ss) ss(10)
#define PP_REPEAT_12(ss) PP_REPEAT_11(ss) ss(11)
#define PP_REPEAT_13(ss) PP_REPEAT_12(ss) ss(12)
#define PP_REPEAT_14(ss) PP_REPEAT_13(ss) ss(13)
#define PP_REPEAT_15(ss) PP_REPEAT_14(ss) ss(14)
#define PP_REPEAT_16(ss) PP_REPEAT_15(ss) ss(15)
#define PP_REPEAT_17(ss) PP_REPEAT_16(ss) ss(16)
#define PP_REPEAT_18(ss) PP_REPEAT_17(ss) ss(17)
#define PP_REPEAT_19(ss) PP_REPEAT_18(ss) ss(18)
#define PP_REPEAT_20(ss) PP_REPEAT_19(ss) ss(19)
#define PP_REPEAT_21(ss) PP_REPEAT_20(ss) ss(20)
#define PP_REPEAT_22(ss) PP_REPEAT_21(ss) ss(21)
#define PP_REPEAT_23(ss) PP_REPEAT_22(ss) ss(22)
#define PP_REPEAT_24(ss) PP_REPEAT_23(ss) ss(23)
#define PP_REPEAT_25(ss) PP_REPEAT_24(ss) ss(24)
#define PP_REPEAT_26(ss) PP_REPEAT_25(ss) ss(25)
#define PP_REPEAT_27(ss) PP_REPEAT_26(ss) ss(26)
#define PP_REPEAT_28(ss) PP_REPEAT_27(ss) ss(27)
#define PP_REPEAT_29(ss) PP_REPEAT_28(ss) ss(28)
#define PP_REPEAT_30(ss) PP_REPEAT_29(ss) ss(29)
#define PP_REPEAT_31(ss) PP_REPEAT_30(ss) ss(30)
#define PP_REPEAT_32(ss) PP_REPEAT_31(ss) ss(31)
#define PP_REPEAT_33(ss) PP_REPEAT_32(ss) ss(32)
#define PP_REPEAT_34(ss) PP_REPEAT_33(ss) ss(33)
#define PP_REPEAT_35(ss) PP_REPEAT_34(ss) ss(34)
#define PP_REPEAT_36(ss) PP_REPEAT_35(ss) ss(35)
#define PP_REPEAT_37(ss) PP_REPEAT_36(ss) ss(36)
#define PP_REPEAT_38(ss) PP_REPEAT_37(ss) ss(37)
#define PP_REPEAT_39(ss) PP_REPEAT_38(ss) ss(38)
#define PP_REPEAT_40(ss) PP_REPEAT_39(ss) ss(39)
#define PP_REPEAT_41(ss) PP_REPEAT_40(ss) ss(40)
#define PP_REPEAT_42(ss) PP_REPEAT_41(ss) ss(41)
#define PP_REPEAT_43(ss) PP_REPEAT_42(ss) ss(42)
#define PP_REPEAT_44(ss) PP_REPEAT_43(ss) ss(43)
#define PP_REPEAT_45(ss) PP_REPEAT_44(ss) ss(44)
#define PP_REPEAT_46(ss) PP_REPEAT_45(ss) ss(45)
#define PP_REPEAT_47(ss) PP_REPEAT_46(ss) ss(46)
#define PP_REPEAT_48(ss) PP_REPEAT_47(ss) ss(47)
#define PP_REPEAT_49(ss) PP_REPEAT_48(ss) ss(48)
#define PP_REPEAT_50(ss) PP_REPEAT_49(ss) ss(49)
#define PP_REPEAT_51(ss) PP_REPEAT_50(ss) ss(50)
#define PP_REPEAT_52(ss) PP_REPEAT_51(ss) ss(51)
#define PP_REPEAT_53(ss) PP_REPEAT_52(ss) ss(52)
#define PP_REPEAT_54(ss) PP_REPEAT_53(ss) ss(53)
#define PP_REPEAT_55(ss) PP_REPEAT_54(ss) ss(54)
#define PP_REPEAT_56(ss) PP_REPEAT_55(ss) ss(55)
#define PP_REPEAT_57(ss) PP_REPEAT_56(ss) ss(56)
#define PP_REPEAT_58(ss) PP_REPEAT_57(ss) ss(57)
#define PP_REPEAT_59(ss) PP_REPEAT_58(ss) ss(58)
#define PP_REPEAT_60(ss) PP_REPEAT_59(ss) ss(59)
#define PP_REPEAT_61(ss) PP_REPEAT_60(ss) ss(60)
#define PP_REPEAT_62(ss) PP_REPEAT_61(ss) ss(61)
#define PP_REPEAT_63(ss) PP_REPEAT_62(ss) ss(62)
#define PP_REPEAT_64(ss) PP_REPEAT_63(ss) ss(63)

#define PP_REPEAT__(N, X) PP_EXPAND(PP_REPEAT_ ## N)(X)
#define PP_REPEAT_(N, X) PP_REPEAT__(N, X)
#define PP_REPEAT(N, X) PP_REPEAT_(PP_EXPAND(N), X)


#ifdef __cplusplus
}
#endif


#endif /* __ZFEX_PP_H */
