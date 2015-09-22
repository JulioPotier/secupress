<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_settings_section( 'secupress_display_white_label', __( 'White Label', 'secupress' ), '__secupress_whitelabel_info', 'secupress_white-label' );

/**
 * Used by premium version to add the right fields. Developpers: don't use it ;)
 *
 * @since 1.0
 */
do_action( 'premium.module.white-label' );

if ( ! has_action( 'premium.module.white-label' ) ) {

	add_settings_field(
		'secupress_need_premium',
		__( 'Premium Upgrade', 'secupress' ),
		'secupress_button',
		'secupress_white-label',
		'secupress_display_white_label',
		array(
			'button' =>
			array(
				'button_label' => __( 'Premium Upgrade', 'secupress' ),
				'url'   => '#', ////
			),
			'helper_help' =>
			array(
				'name'			=> 'need_premium',
				'description'	=> __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' )
			),
		)
	);

}

function __secupress_whitelabel_info() {
	_e( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated.', 'secupress' );
	echo '<hr>';
}