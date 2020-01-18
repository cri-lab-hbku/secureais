/*
   Copyright (C) 2019 MIRACL UK Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.


    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

     https://www.gnu.org/licenses/agpl-3.0.en.html

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   You can be released from the requirements of the license by purchasing
   a commercial license. Buying such a license is mandatory as soon as you
   develop commercial activities involving the MIRACL Core Crypto SDK
   without disclosing the source code of your own applications, or shipping
   the MIRACL Core Crypto SDK with a closed source product.
*/

#ifndef ECP_NUMS384W_H
#define ECP_NUMS384W_H

#include "fp_F384PM.h"
#include "config_curve_NUMS384W.h"

using namespace core;

namespace NUMS384W {

/* Curve Params - see rom.c */
extern const int CURVE_A;     /**< Elliptic curve A parameter */
extern const int CURVE_B_I;
extern const int CURVE_Cof_I;
extern const B384_56::BIG CURVE_B;     /**< Elliptic curve B parameter */
extern const B384_56::BIG CURVE_Order; /**< Elliptic curve group order */
extern const B384_56::BIG CURVE_Cof;   /**< Elliptic curve cofactor */

/* Generator point on G1 */
extern const B384_56::BIG CURVE_Gx; /**< x-coordinate of generator point in group G1  */
extern const B384_56::BIG CURVE_Gy; /**< y-coordinate of generator point in group G1  */


/* For Pairings only */

/* Generator point on G2 */
extern const B384_56::BIG CURVE_Pxa; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxb; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pya; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyb; /**< imaginary part of y-coordinate of generator point in group G2 */

/*** needed for BLS24 curves ***/

extern const B384_56::BIG CURVE_Pxaa; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxab; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxba; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxbb; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyaa; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyab; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyba; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pybb; /**< imaginary part of y-coordinate of generator point in group G2 */

/*** needed for BLS48 curves ***/

extern const B384_56::BIG CURVE_Pxaaa; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxaab; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxaba; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxabb; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxbaa; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxbab; /**< imaginary part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxbba; /**< real part of x-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pxbbb; /**< imaginary part of x-coordinate of generator point in group G2 */

extern const B384_56::BIG CURVE_Pyaaa; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyaab; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyaba; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pyabb; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pybaa; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pybab; /**< imaginary part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pybba; /**< real part of y-coordinate of generator point in group G2 */
extern const B384_56::BIG CURVE_Pybbb; /**< imaginary part of y-coordinate of generator point in group G2 */



extern const B384_56::BIG CURVE_Bnx; /**< BN curve x parameter */

extern const B384_56::BIG CURVE_Cru; /**< BN curve Cube Root of Unity */

extern const B384_56::BIG Fra; /**< real part of BN curve Frobenius Constant */
extern const B384_56::BIG Frb; /**< imaginary part of BN curve Frobenius Constant */


extern const B384_56::BIG CURVE_W[2];	 /**< BN curve constant for GLV decomposition */
extern const B384_56::BIG CURVE_SB[2][2]; /**< BN curve constant for GLV decomposition */
extern const B384_56::BIG CURVE_WB[4];	 /**< BN curve constant for GS decomposition */
extern const B384_56::BIG CURVE_BB[4][4]; /**< BN curve constant for GS decomposition */


/**
	@brief ECP structure - Elliptic Curve Point over base field
*/

typedef struct
{
//    int inf; /**< Infinity Flag - not needed for Edwards representation */

    F384PM::FP x; /**< x-coordinate of point */
#if CURVETYPE_NUMS384W!=MONTGOMERY
    F384PM::FP y; /**< y-coordinate of point. Not needed for Montgomery representation */
#endif
    F384PM::FP z;/**< z-coordinate of point */
} ECP;


/* ECP E(Fp) prototypes */
/**	@brief Tests for ECP point equal to infinity
 *
	@param P ECP point to be tested
	@return 1 if infinity, else returns 0
 */
extern int ECP_isinf(ECP *P);
/**	@brief Tests for equality of two ECPs
 *
	@param P ECP instance to be compared
	@param Q ECP instance to be compared
	@return 1 if P=Q, else returns 0
 */
extern int ECP_equals(ECP *P, ECP *Q);
/**	@brief Copy ECP point to another ECP point
 *
	@param P ECP instance, on exit = Q
	@param Q ECP instance to be copied
 */
extern void ECP_copy(ECP *P, ECP *Q);
/**	@brief Negation of an ECP point
 *
	@param P ECP instance, on exit = -P
 */
extern void ECP_neg(ECP *P);
/**	@brief Set ECP to point-at-infinity
 *
	@param P ECP instance to be set to infinity
 */
extern void ECP_inf(ECP *P);
/**	@brief Calculate Right Hand Side of curve equation y^2=f(x)
 *
	Function f(x) depends on form of elliptic curve, Weierstrass, Edwards or Montgomery.
	Used internally.
	@param r BIG n-residue value of f(x)
	@param x BIG n-residue x
 */
extern void ECP_rhs(F384PM::FP *r, F384PM::FP *x);
/**	@brief Set ECP to point(x,y) given just x and sign of y
 *
	Point P set to infinity if no such point on the curve. If x is on the curve then y is calculated from the curve equation.
	The correct y value (plus or minus) is selected given its sign s.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@param s an integer representing the "sign" of y, in fact its least significant bit.
 */
extern int ECP_setx(ECP *P, B384_56::BIG x, int s);

#if CURVETYPE_NUMS384W==MONTGOMERY
/**	@brief Set ECP to point(x,[y]) given x
 *
	Point P set to infinity if no such point on the curve. Note that y coordinate is not needed.
	@param P ECP instance to be set (x,[y])
	@param x BIG x coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_set(ECP *P, B384_56::BIG x);
/**	@brief Extract x coordinate of an ECP point P
 *
	@param x BIG on exit = x coordinate of point
	@param P ECP instance (x,[y])
	@return -1 if P is point-at-infinity, else 0
 */
extern int ECP_get(B384_56::BIG x, ECP *P);
/**	@brief Adds ECP instance Q to ECP instance P, given difference D=P-Q
 *
	Differential addition of points on a Montgomery curve
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
	@param D Difference between P and Q
 */
extern void ECP_add(ECP *P, ECP *Q, ECP *D);
#else
/**	@brief Set ECP to point(x,y) given x and y
 *
	Point P set to infinity if no such point on the curve.
	@param P ECP instance to be set (x,y)
	@param x BIG x coordinate of point
	@param y BIG y coordinate of point
	@return 1 if point exists, else 0
 */
extern int ECP_set(ECP *P, B384_56::BIG x, B384_56::BIG y);
/**	@brief Extract x and y coordinates of an ECP point P
 *
	If x=y, returns only x
	@param x BIG on exit = x coordinate of point
	@param y BIG on exit = y coordinate of point (unless x=y)
	@param P ECP instance (x,y)
	@return sign of y, or -1 if P is point-at-infinity
 */
extern int ECP_get(B384_56::BIG x, B384_56::BIG y, ECP *P);
/**	@brief Adds ECP instance Q to ECP instance P
 *
	@param P ECP instance, on exit =P+Q
	@param Q ECP instance to be added to P
 */
extern void ECP_add(ECP *P, ECP *Q);
/**	@brief Subtracts ECP instance Q from ECP instance P
 *
	@param P ECP instance, on exit =P-Q
	@param Q ECP instance to be subtracted from P
 */
extern void ECP_sub(ECP *P, ECP *Q);
#endif
/**	@brief Converts an ECP point from Projective (x,y,z) coordinates to affine (x,y) coordinates
 *
	@param P ECP instance to be converted to affine form
 */
extern void ECP_affine(ECP *P);
/**	@brief Formats and outputs an ECP point to the console, in projective coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_outputxyz(ECP *P);
/**	@brief Formats and outputs an ECP point to the console, converted to affine coordinates
 *
	@param P ECP instance to be printed
 */
extern void ECP_output(ECP * P);

/**	@brief Formats and outputs an ECP point to the console
 *
	@param P ECP instance to be printed
 */
extern void ECP_rawoutput(ECP * P);

/**	@brief Formats and outputs an ECP point to an octet string
 *
	The octet string is normally in the standard form 0x04|x|y
	Here x (and y) are the x and y coordinates in left justified big-endian base 256 form.
	For Montgomery curve it is 0x06|x
	If c is true, only the x coordinate is provided as in 0x2|x if y is even, or 0x3|x if y is odd
	@param c compression required, true or false
	@param S output octet string
	@param P ECP instance to be converted to an octet string
 */
extern void ECP_toOctet(octet *S, ECP *P, bool c);
/**	@brief Creates an ECP point from an octet string
 *
	The octet string is normally in the standard form 0x04|x|y
	Here x (and y) are the x and y coordinates in left justified big-endian base 256 form.
	For Montgomery curve it is 0x06|x
	If in compressed form only the x coordinate is provided as in 0x2|x if y is even, or 0x3|x if y is odd
	@param P ECP instance to be created from the octet string
	@param S input octet string
    @param c true for compression
	return 1 if octet string corresponds to a point on the curve, else 0
 */
extern int ECP_fromOctet(ECP *P, octet *S);
/**	@brief Doubles an ECP instance P
 *
	@param P ECP instance, on exit =2*P
 */
extern void ECP_dbl(ECP *P);
/**	@brief Multiplies an ECP instance P by a small integer, side-channel resistant
 *
	@param P ECP instance, on exit =i*P
	@param i small integer multiplier
	@param b maximum number of bits in multiplier
 */
extern void ECP_pinmul(ECP *P, int i, int b);
/**	@brief Multiplies an ECP instance P by a BIG, side-channel resistant
 *
	Uses Montgomery ladder for Montgomery curves, otherwise fixed sized windows.
	@param P ECP instance, on exit =b*P
	@param b BIG number multiplier

 */
extern void ECP_mul(ECP *P, B384_56::BIG b);
/**	@brief Calculates double multiplication P=e*P+f*Q, side-channel resistant
 *
	@param P ECP instance, on exit =e*P+f*Q
	@param Q ECP instance
	@param e BIG number multiplier
	@param f BIG number multiplier
 */
extern void ECP_mul2(ECP *P, ECP *Q, B384_56::BIG e, B384_56::BIG f);

/**	@brief Multiplies random point by co-factor
 *
	@param Q ECP multiplied by co-factor
 */
extern void ECP_cfp(ECP *Q);

/**	@brief Hashes random BIG to curve point
 *
	@param Q ECP instance 
	@param x Fp derived from hash
 */
extern void ECP_hashit(ECP *Q, B384_56::BIG  x);


/**	@brief Maps random octet to curve point of correct order
 *
	@param Q ECP instance of correct order
	@param w OCTET byte array to be mapped
 */
extern void ECP_mapit(ECP *Q, octet *w);

/**	@brief Get Group Generator from ROM
 *
	@param G ECP instance
    @return true or false
 */
extern int ECP_generator(ECP *G);

}

#endif
