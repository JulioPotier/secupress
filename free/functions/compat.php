<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( secupress_is_function_disabled( 'gmp_nextprime' ) ) {

	/**
	 * Find next prime number
	 *
	 * @since 2.2.6
	 * @author Julio Potier
	 * 
	 * @param (int) $n
	 * @return (int) $n
	 **/
	function gmp_nextprime( $n ) {
		if ( $n < 2 ) {
			return 2;
		}
		if ($n === 2) {
			return 3;
		}
		$x = ( $n % 2 === 0 ) ? $n + 1 : $n + 2;
		while ( true ) {
			$sqrt_x = sqrt( $x );
			$is_prime = true;
			for ( $i = 3; $i <= $sqrt_x; $i += 2 ) {
				if ( $x % $i === 0 ) {
					$is_prime = false;
					break;
				}
			}
			if ( $is_prime ) {
				return $x;
			}
			$x += 2;
		}
	}
}