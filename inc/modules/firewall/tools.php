<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** MAKE SURE OUR LISTS ARE NOT EMPTY: FILTER OUTPUT ============================================ */
/** --------------------------------------------------------------------------------------------- */

/**
 * Bad User Agents.
 */
add_filter( 'pre_secupress_get_module_option_bbq-headers_user-agents-list', 'secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden user-agents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The filtered value. Should be `null` by default.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_pre_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


add_filter( 'secupress_get_module_option_bbq-headers_user-agents-list', 'secupress_firewall_bbq_headers_user_agents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden user-agents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The option value.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_bbq_headers_user_agents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_headers_user_agents_list_default();
	}
	return $value;
}


/**
 * Bad URL contents.
 */
add_filter( 'pre_secupress_get_module_option_bbq-url-content_bad-contents-list', 'secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden contents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The filtered value. Should be `null` by default.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_pre_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && isset( $value ) && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


add_filter( 'secupress_get_module_option_bbq-url-content_bad-contents-list', 'secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty', PHP_INT_MAX, 3 );
/**
 * Filter the option to not return an empty list of forbidden contents.
 *
 * @since 1.0
 *
 * @param (mixed)  $value   The option value.
 * @param (string) $default The default value.
 * @param (string) $module  The module.
 *
 * @return (string)
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default_if_empty( $value, $default, $module ) {
	if ( 'firewall' === $module && ! trim( $value ) ) {
		return secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
	return $value;
}


/**
 * Get contents forbidden in URL by default.
 *
 * @since 1.0
 *
 * @return (string) A comma-separated list.
 */
function secupress_firewall_bbq_url_content_bad_contents_list_default() {
	return 'AND 1=, AND+1=, AND%201=, information_schema, UNI' . 'ON SEL' . 'ECT, UNI' . 'ON+SEL' . 'ECT, UNI' . 'ON%20SEL' . 'ECT, UNI' . 'ON ALL SEL' . 'ECT, UNI' . 'ON+ALL+SEL' . 'ECT, UNI' . 'ON%20ALL%20SEL' . 'ECT, ev' . 'al(, wp-config.php, %' . '00, %%' . '30%' . '30, GLOBALS[, .ini, REQUEST[, et' . 'c/pas' . 'swd, ba' . 'se' . '64' . '_en' . 'co' . 'de, ba' . 'se' . '64' . '_de' . 'co' . 'de, javascript:, ../, 127.0.0.1, inp' . 'ut_fi' . 'le';
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'secupress_block_id', 'secupress_firewall_block_id' );
/**
 * Translate block IDs into understandable things.
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
		// URL Contents.
		'BUC'  => __( 'Bad URL Contents', 'secupress' ),
		// GeoIP.
		'GIP'  => __( 'GeoIP', 'secupress' ),
		// Request Method.
		'RMHM' => __( 'Bad Request Method', 'secupress' ),
		// User-Agent.
		'UAHT' => __( 'User-Agent With HTML Tags', 'secupress' ),
		'UAHB' => __( 'User-Agent Blacklisted', 'secupress' ),
	);

	return isset( $block_ids[ $module ] ) ? $block_ids[ $module ] : $module;
}
