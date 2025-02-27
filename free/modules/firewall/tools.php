<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================ */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get user-agents forbidden by default.
 *
 * @since 2.2.6 Malwares are now loaded from the file
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_headers_user_agents_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! empty( $list ) ) {
		return $list;
	}

	$filename = SECUPRESS_INC_PATH . 'data/bad_user_agents.data';
	if ( file_exists( $filename ) ) {
		$list = file_get_contents( $filename );
	}
	/**
	 * Filters the bad user agents
	 * @since 1.0
	 * 
	 * @param (array) $list
	*/
	$list = apply_filters( 'secupress.bad_user_agents.list', $list );
	secupress_cache_data( __FUNCTION__, $list );

	return $list;
}

/**
 * Get contents forbidden in URL by default.
 *
 * @since 2.2.6 Malwares are now loaded from the file
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! empty( $list ) ) {
		return $list;
	}
	
	$filename = SECUPRESS_INC_PATH . 'data/bad_url_contents.data';
	if ( file_exists( $filename ) ) {
		$list = file_get_contents( $filename );
	}
	/**
	 * Filters the bad url contents
	 * @since 1.0
	 * 
	 * @param (array) $list
	*/
	$list = apply_filters( 'secupress.bad_url_contents.list', $list );
	secupress_cache_data( __FUNCTION__, $list );

	return $list;
}

/**
 * Get contents forbidden in REMOTE_HOST by default.
 *
 * @since 2.2.6 Malwares are now loaded from the file
 * @since 1.4.9
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_host_content_bad_contents_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! empty( $list ) ) {
		return $list;
	}

	$filename = SECUPRESS_INC_PATH . 'data/bad_host_contents.data';
	if ( file_exists( $filename ) ) {
		$list = file_get_contents( $filename );
	}
	/**
	 * Filters the bad host contents
	 * @since 1.0
	 * 
	 * @param (array) $list
	*/
	$list = apply_filters( 'secupress.bad_host_contents.list', $list );
	secupress_cache_data( __FUNCTION__, $list );

	return $list;
}

/**
 * Get contents forbidden in HTTP_REFERER by default.
 *
 * @since 2.2.6 Malwares are now loaded from the file
 * @since 1.4.9
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_referer_content_bad_contents_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! empty( $list ) ) {
		return $list;
	}

	$filename = SECUPRESS_PRO_INC_PATH . 'data/bad_referer_contents.data';
	if ( file_exists( $filename ) ) {
		$list = file_get_contents( $filename );
	}
	/**
	 * Filters the bad referer contents
	 * @since 1.0
	 * 
	 * @param (array) $list
	*/
	$list = apply_filters( 'secupress.bad_referer_contents.list', $list );
	secupress_cache_data( __FUNCTION__, $list );

	return $list;
}

/**
 * Get forbidden keys in $_REQUEST array
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_request_content_bad_contents_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! is_null( $list ) ) {
		return $list;
	} else {
		$list = '';
	}
	$filename = SECUPRESS_INC_PATH . 'data/bad_request_keys.data';
	if ( empty( $list ) && file_exists( $filename ) ) {
		$list = explode( ',', file_get_contents( $filename ) );
	}
	/**
	 * Filters the bad request keys
	 * @since 2.2.6
	 * 
	 * @param (array) $list
	*/
	$list = apply_filters( 'secupress.bad_request_keys.list', $list );
	secupress_cache_data( __FUNCTION__, $list );
	// We do the job here because the usual function secupress_block_bad_content_but_what() waits for a $_SERVER key, this is not.
	$matches = secupress_check_request_keys( $list );
	if ( $list && $matches ) {
		secupress_block( 'BUK', [ 'code' => 503, 'b64' => [ 'data' => $matches ], 'attack_type' => 'bad_request_content' ] );
	}
	return []; // no need to preg_match on this one
}

/**
 * Get AI Bots list
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_referer_content_ai_bots_list_default() {
	$list     = secupress_cache_data( __FUNCTION__ );
	if ( ! is_null( $list ) ) {
		return $list;
	} else {
		$list = '';
	}

	$filename = SECUPRESS_PRO_INC_PATH . 'data/ai_bots.data';
	if ( file_exists( $filename ) ) {
		$list = file_get_contents( $filename );
	}
	/**
	 * Filters the AI list
	 * @since 2.2.6
	 * 
	 * @param (array) $list
	*/
	$list     = apply_filters( 'secupress.ai_bots.list', $list );
	secupress_cache_data( __FUNCTION__, $list );

	return $list;
}

/** --------------------------------------------------------------------------------------------- */
/** OTHER ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Detect if a group of word is present in $_REQUEST
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (string|bool)
 **/
function secupress_check_request_keys( $keys ) {
	$groups = explode( ',', $keys );
	foreach ( $groups as $group ) {
		$words = explode( ' ', $group );
		$all_present = true;
		foreach ( $words as $word ) {
			if ( ! isset( $_REQUEST[ $word ] ) ) {
				$all_present = false;
				break;
			}
		}
		if ( $all_present ) {
			return $group;
		}
	}
	return false;
}

/**
 * See secupress_block_bad_url_contents
 *
 * @since 1.4.9
 * @author Julio Potier
 * @param (string) $function Short string to be concat to form the callback
 * @param (string) $server The index in $_SERVER to be checked
 * @param (string) $block_id Which code use if we block
 **/
function secupress_block_bad_content_but_what( $function, $server, $block_id ) {
	if ( ! isset( $_SERVER[ $server ] ) ) {
		return;
	}

	// don't block if our own domain name contains a bad word and is present in the URL (with redirect for example).
	$check_value = isset( $_SERVER['HTTP_HOST'] ) ? str_replace( $_SERVER['HTTP_HOST'], '', $_SERVER[ $server ] ) : $_SERVER[ $server ];
	$check_value = explode( '?', $check_value, 2 );
	// Nothing like a request uri? It's ok, don't look into the URLs paths
	if ( 'QUERY_STRING' !== $server && ! isset( $check_value[1] ) ) {
		return;
	}
	$check_value  = end( $check_value );
	$bad_contents = "secupress_firewall_bbq_{$function}_content_bad_contents_list_default";
	if ( ! function_exists( $bad_contents ) ) {
		wp_die( esc_html( __FUNCTION__ ) ); // Should not happen in live.
	}
	$bad_contents = $bad_contents();

	if ( ! empty( $bad_contents ) ) {
		if ( is_array( $bad_contents ) ) {
			$bad_contents = implode( ',', $bad_contents );
		}
		$bad_contents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_contents, '/' ) );
		$bad_contents = trim( $bad_contents, '| ' );

		while ( false !== strpos( $bad_contents, '||' ) ) {
			$bad_contents = str_replace( '||', '|', $bad_contents );
		}

		preg_match( '/' . $bad_contents . '/i', $check_value, $matches );
		if ( ! empty( $check_value ) && $bad_contents && ! empty( $matches ) ) {
			secupress_block( $block_id, [ 'code' => 503, 'b64' => [ 'data' => $matches ], 'attack_type' => 'bad_request_content' ] );
		}
	}

}

add_filter( 'secupress_block_id', 'secupress_firewall_block_id' );
/**
 * Translate block IDs into understandable things.
 *
 * @since 2.2.6 BRK, UAAI
 * @since 2.3   ATS
 * @since 2.1   NOUSER
 * @since 2.0   BRU
 * @since 1.4.9 BHC, BRC
 * @author Julio Potier
 * 
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (string) $module The related module.
 *
 * @return (string) The block ID.
 */
function secupress_firewall_block_id( $module ) {
	$block_ids = array(
		// Antispam.
		'AAU'  => __( 'Antispam, Anti-Usurpation', 'secupress' ),
		'ATS'  => __( 'Antispam, Too soon', 'secupress' ),
		// Firewall.
		'BRU'  => __( 'Bad Referer URL', 'secupress' ),
		// URL Contents.
		'BRK'  => __( 'Bad Request Keys', 'secupress' ),
		'BUC'  => __( 'Bad URL Contents', 'secupress' ),
		'BHC'  => __( 'Bad Host Contents', 'secupress' ),
		'BRC'  => __( 'Bad Referer Contents', 'secupress' ),
		// GeoIP.
		'GIP'  => __( 'Bad GeoIP', 'secupress' ),
		// User-Agent.
		'UAHT' => __( 'User-Agent With HTML Tags', 'secupress' ),
		'UAHB' => __( 'User-Agent Disallowed', 'secupress' ),
		'UAAI' => __( 'User-Agent is AI Bot', 'secupress' ),
		// Users
		'NOUSER' => __( 'Unknown User', 'secupress' ),
		// Files & functions
		'PHP404' => __( '404 on PHP file', 'secupress' ),
		'FUNCTS' => __( 'Functions in HTTP request', 'secupress' ),
	);

	return isset( $block_ids[ $module ] ) ? $block_ids[ $module ] : $module;
}
