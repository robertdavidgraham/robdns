/* Copyright: (c) 2009-2010 by Robert David Graham
** License: This code is private to the author, and you do not 
** have a license to run it, or own a copy, unless given 
** a license personally by the author. This is 
** explained in the LICENSE file at the root of the project. 
**/
#ifndef EXTRACT_H
#define EXTRACT_H

#define ex32be(px)  (   *((unsigned char*)(px)+0)<<24 \
                    |   *((unsigned char*)(px)+1)<<16 \
                    |   *((unsigned char*)(px)+2)<< 8 \
                    |   *((unsigned char*)(px)+3)<< 0 )
#define ex32le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 \
                    |   *((unsigned char*)(px)+3)<<24 )
#define ex16be(px)  (   *((unsigned char*)(px)+0)<< 8 \
                    |   *((unsigned char*)(px)+1)<< 0 )
#define ex16le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 )

#define ex24be(px)  (   *((unsigned char*)(px)+0)<<16 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<< 0 )
#define ex24le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 )

#define ex64be(px)  ( (((uint64_t)ex32be(px))<<32L) + ((uint64_t)ex32be((px)+4)) )
#define ex64le(px)  ( ((uint64_t)ex32be(px)) + (((uint64_t)ex32be((px)+4))<<32L) )

#endif
