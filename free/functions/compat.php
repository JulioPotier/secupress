<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Find next prime number
 *
 * @since 2.3.14 function named secupress_next_prime()
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (int) $n
 * @return (int) $n
 **/
function secupress_next_prime( $n ) {
	if ( function_exists( 'gmp_nextprime' ) && ! secupress_is_function_disabled( 'gmp_nextprime' ) ) {
		return (int) gmp_nextprime( $n );
	}
	$c = $n + ( ( $n <= 2 ? 3 - $n : $n % 2 ) ? 2 : 1 );
	while ( true ) { // Finding a prime is mandatory.
		$m = (int) sqrt( $c ) + 1;
		$i = 3;
		while ( $i <= $m ) {
			if ( $c % $i++ === 0 ) {
				break;
			}
			++$i;
		}
		if ( $i > $m ) {
			return $c;
		}
		$c += 2;
	}
}