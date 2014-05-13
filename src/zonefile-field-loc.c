#include "zonefile-fields.h"
#include <ctype.h>
#include <string.h>


enum LocationField {
    $LATITUDE_DEGREES,
    $LATITUDE_MINUTES,
    $LATITUDE_SECONDS,
    $LATITUDE_SECONDS_FRACTION,
    $LONGITUDE_DEGREES,
    $LONGITUDE_MINUTES,
    $LONGITUDE_SECONDS,
    $LONGITUDE_SECONDS_FRACTION,
    $ALTITUDE, $ALTITUDE_FRACTION,
    $SIZE, $SIZE_FRACTION,
    $HORIZONTAL_PRECISION, $HORIZONTAL_FRACTION,
    $VERTICAL_PRECISION, $VERTICAL_FRACTION,
};

/****************************************************************************
 ****************************************************************************/
void
mm_location_start(struct ZoneFileParser *parser)
{
    memset(&parser->rr_location, 0, sizeof(parser->rr_location));
    parser->s2 = 0;
}

/****************************************************************************
 * Convert the number of centimeter into an RFC1876 'size' specificaiton.
 * This is used to represent the size of the object, as well as the
 * horizontal and vertizal precision.
 *
 ****************************************************************************/
static unsigned char
centimeters_to_size(unsigned number)
{
    unsigned base;
    unsigned power = 0;
    unsigned x = 1;

  
    /* RFC 1876:
             The diameter of a sphere enclosing the described entity, in
             centimeters, expressed as a pair of four-bit unsigned
             integers, each ranging from zero to nine, with the most
             significant four bits representing the base and the second
             number representing the power of ten by which to multiply
             the base.  This allows sizes from 0e0 (<1cm) to 9e9
             (90,000km) to be expressed.  This representation was chosen
             such that the hexadecimal representation can be read by
             eye; 0x15 = 1e5.  Four-bit values greater than 9 are
             undefined, as are values with a base of zero and a non-zero
             exponent.

             Since 20000000m (represented by the value 0x29) is greater
             than the equatorial diameter of the WGS 84 ellipsoid
             (12756274m), it is therefore suitable for use as a
             "worldwide" size.
    */

    /* find the exponent */
    while (x*10 <= number) {
        x *= 10;
        power++;
    }

    /* find the base */
    base = number/x;

    /*
     * Now combine the two nibbles together.
     * TODO: we should validate that both are 9 or less.
     */
    return (unsigned char)((base<<4) | (power&0xF));
}

/****************************************************************************
 ****************************************************************************/
void
mm_location_end(struct ZoneFileParser *parser)
{
    unsigned char *px = parser->block->buf + parser->block->offset;

    if (parser->rr_location.field <= $SIZE)
        parser->rr_location.size = 100; /* default = 1e2 cm = 1.00m */
    if (parser->rr_location.field <= $HORIZONTAL_PRECISION)
        parser->rr_location.horiz_pre = 1000000; /* default = 1e6 cm = 10000.00m = 10km */
    if (parser->rr_location.field <= $VERTICAL_PRECISION)
        parser->rr_location.vert_pre = 1000; /* default = 1e3 cm = 10.00m */

    /*
      MSB                                           LSB
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  0|        VERSION        |         SIZE          |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  2|       HORIZ PRE       |       VERT PRE        |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  4|                   LATITUDE                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  6|                   LATITUDE                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  8|                   LONGITUDE                   |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 10|                   LONGITUDE                   |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 12|                   ALTITUDE                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 14|                   ALTITUDE                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
    memset(px, 0, 16);

    px[ 0] = 0; /*version */
    px[ 1] = centimeters_to_size(parser->rr_location.size);
    px[ 2] = centimeters_to_size(parser->rr_location.horiz_pre);
    px[ 3] = centimeters_to_size(parser->rr_location.vert_pre);
    px[ 4] = (unsigned char)(parser->rr_location.latitude >> 24);
    px[ 5] = (unsigned char)(parser->rr_location.latitude >> 16);
    px[ 6] = (unsigned char)(parser->rr_location.latitude >>  8);
    px[ 7] = (unsigned char)(parser->rr_location.latitude >>  0);
    px[ 8] = (unsigned char)(parser->rr_location.longitude >> 24);
    px[ 9] = (unsigned char)(parser->rr_location.longitude >> 16);
    px[10] = (unsigned char)(parser->rr_location.longitude >>  8);
    px[11] = (unsigned char)(parser->rr_location.longitude >>  0);
    px[12] = (unsigned char)(parser->rr_location.altitude >> 24);
    px[13] = (unsigned char)(parser->rr_location.altitude >> 16);
    px[14] = (unsigned char)(parser->rr_location.altitude >>  8);
    px[15] = (unsigned char)(parser->rr_location.altitude >>  0);

    parser->block->offset += 16;
}


/****************************************************************************
 ****************************************************************************/
void
mm_location_parse(struct ZoneFileParser *parser, 
    const unsigned char *buf, unsigned *offset, unsigned length)
{
	unsigned i;
	unsigned s = parser->s2;
    unsigned number = parser->rr_location.number;
    unsigned field = parser->rr_location.field;
	
    /*
The LOC record is expressed in a master file in the following format:

owner TTL class LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
                           {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
                           [vp["m"]]]] )

where:

   d1:     [0 .. 90]            (degrees latitude)
   d2:     [0 .. 180]           (degrees longitude)
   m1, m2: [0 .. 59]            (minutes latitude/longitude)
   s1, s2: [0 .. 59.999]        (seconds latitude/longitude)
   alt:    [-100000.00 .. 42849672.95] BY .01 (altitude in meters)
   siz, hp, vp: [0 .. 90000000.00] (size/precision in meters)

If omitted, minutes and seconds default to zero, size defaults to 1m,
horizontal precision defaults to 10000m, and vertical precision
defaults to 10m.  These defaults are chosen to represent typical
ZIP/postal code area sizes, since it is often easy to find
approximate geographical location by ZIP/postal code.
*/
#define IS_LATITUDE(field) ($LATITUDE_DEGREES < (field) && (field) <= $LONGITUDE_DEGREES)
#define IS_LONGITUDE(field) ($LONGITUDE_DEGREES < (field) && (field) <= $ALTITUDE)

	enum {
		$START			= 0,
		$END			= 1,
		$COMMENT		= 2,
		$PARSE_ERROR	= 3,

        $NUMBER_START,
        $NUMBER_CONTINUE,
        $NUMBER_END,

        $END_SPACE
	};

	for (i=*offset; i<length; i++) {
	    unsigned char c;

		if (parse_default2(parser, buf, &i, &length, &c))
			break;

	    switch (s) {
	    case $START:
		    s = $NUMBER_START;

        case $NUMBER_START:
            if (isspace(c))
                break;
            if (isdigit(c)) {
                number = (c - '0');
                parser->rr_location.digits = 1;
                s = $NUMBER_CONTINUE;
                continue;
            } else if ('N' == toupper(c) && IS_LATITUDE(field)) {
                parser->rr_location.latitude |= (1<<31);
                field = $LONGITUDE_DEGREES;
                continue;
            } else if ('S' == toupper(c) && IS_LATITUDE(field)) {
                parser->rr_location.latitude = (1<<31) - parser->rr_location.latitude;
                field = $LONGITUDE_DEGREES;
                continue;
            } else if ('E' == toupper(c) && IS_LONGITUDE(field)) {
                parser->rr_location.longitude |= (1<<31);
                field = $ALTITUDE;
                continue;
            } else if ('W' == toupper(c) && IS_LONGITUDE(field)) {
                parser->rr_location.longitude = (1<<31) - parser->rr_location.longitude;
                field = $ALTITUDE;
                continue;
            } else if ('-' == c && field == $ALTITUDE) {
                parser->rr_location.is_negative = 1;
                continue;
            }  else {
                parse_err(parser, "LOC: unexpected char, field=%u\n", field);
                i = length;
                continue;
            }
            break;

        case $NUMBER_CONTINUE:
            if (isdigit(c)) {
                number = number * 10 + (c - '0');
                parser->rr_location.digits++;
                continue;
            } else if (c == 'm') {
                switch (field) {
                case $ALTITUDE:
                case $ALTITUDE_FRACTION:
                case $SIZE:
                case $SIZE_FRACTION:
                case $HORIZONTAL_PRECISION:
                case $HORIZONTAL_FRACTION:
                case $VERTICAL_PRECISION:
                case $VERTICAL_FRACTION:
                    /* these fields optionally end in 'm' meaning 'meters' */
                    s = $NUMBER_END;
                }
            }
            s = $NUMBER_END;
            /* fall; through */
        case $NUMBER_END:
            switch (field) {
            case $LATITUDE_DEGREES:
                parser->rr_location.latitude = number * 60 * 60 * 1000;
                break;
            case $LATITUDE_MINUTES:
                parser->rr_location.latitude += number * 60 * 1000;
                break;
            case $LATITUDE_SECONDS:
                parser->rr_location.latitude += number * 1000;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $LATITUDE_SECONDS_FRACTION:
                while (parser->rr_location.digits < 3) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                parser->rr_location.latitude += number;
                break;
            case $LONGITUDE_DEGREES:
                parser->rr_location.longitude = number * 60 * 60 * 1000;
                break;
            case $LONGITUDE_MINUTES:
                parser->rr_location.longitude += number * 60 * 1000;
                break;
            case $LONGITUDE_SECONDS:
                parser->rr_location.longitude += number * 1000;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $LONGITUDE_SECONDS_FRACTION:
                while (parser->rr_location.digits < 3) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                while (parser->rr_location.digits > 3) {
                    parser->rr_location.digits++;
                    number /= 10;
                }
                parser->rr_location.longitude += number;
                break;
            case $ALTITUDE:
                if (parser->rr_location.is_negative) {
                    parser->rr_location.altitude = 10000000 - number*100;
                } else
                    parser->rr_location.altitude = 10000000 + number*100;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $ALTITUDE_FRACTION:
                while (parser->rr_location.digits < 2) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                while (parser->rr_location.digits > 2) {
                    parser->rr_location.digits++;
                    number /= 10;
                }
                if (parser->rr_location.is_negative) {
                    parser->rr_location.altitude -= number;
                } else
                    parser->rr_location.altitude += number;
                break;
            case $SIZE:
                parser->rr_location.size = number*100;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $SIZE_FRACTION:
                while (parser->rr_location.digits < 2) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                while (parser->rr_location.digits > 2) {
                    parser->rr_location.digits++;
                    number /= 10;
                }
                parser->rr_location.size += number;
                break;
            case $HORIZONTAL_PRECISION:
                parser->rr_location.horiz_pre = number*100;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $HORIZONTAL_FRACTION:
                while (parser->rr_location.digits < 2) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                while (parser->rr_location.digits > 2) {
                    parser->rr_location.digits++;
                    number /= 10;
                }
                parser->rr_location.horiz_pre += number;
                break;
            case $VERTICAL_PRECISION:
                parser->rr_location.vert_pre = number*100;
                if (c == '.')
                    c = ' ';
                else
                    field++;
                break;
            case $VERTICAL_FRACTION:
                while (parser->rr_location.digits < 2) {
                    parser->rr_location.digits++;
                    number *= 10;
                }
                while (parser->rr_location.digits > 2) {
                    parser->rr_location.digits++;
                    number /= 10;
                }
                parser->rr_location.vert_pre += number;
                break;
            }
            if (++field <= $VERTICAL_FRACTION)
                s = $NUMBER_START;
            else
                s = $END_SPACE;
            break;
        case $END_SPACE:
            if (!isspace(c)) {
                parse_err(parser, "%s: unexpected characters after end\n", "LOC");
                i = 0;
                continue;
            }
            break;
        }

        if (buf[i] == '\n' && !parser->is_multiline)
            break;
	}
    
	parser->rr_location.number = number;
    parser->rr_location.field = (unsigned char)field;
	parser->s2 = s;
	*offset = i;
}

