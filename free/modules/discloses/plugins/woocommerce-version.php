<?php
/**
 * Module Name: WooCommerce Version Disclosure
 * Description: Remove the generator meta tag, the version from the script tags, and the version from the style tags.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( ! class_exists( 'WooCommerce' ) ) {
	return;
}

/**
 * Remove the WooCommerce generator meta tag.
 *
 * @since 1.0
 */
remove_action( 'get_the_generator_html',  'wc_generator_tag' );
remove_action( 'get_the_generator_xhtml', 'wc_generator_tag' );


add_filter( 'script_loader_src', 'secupress_replace_woocommerce_version_in_src', PHP_INT_MAX );
add_filter( 'style_loader_src',  'secupress_replace_woocommerce_version_in_src', PHP_INT_MAX );
/**
 * Replace the WooCommerce version with a fake version in script and style src.
 *
 * @param (string) $src A content containing the string `ver={$wc_version}`.
 *
 * @return (string)
 */
function secupress_replace_woocommerce_version_in_src( $src ) {
	$hash = secupress_generate_hash( WC_VERSION );

	return str_replace( 'ver=' . WC_VERSION, 'ver=' . $hash, $src );
}
