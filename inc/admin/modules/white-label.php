<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


$this->set_current_section( 'secupress_display_white_label' );
$this->set_section_description( __( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated.', 'secupress' ) );
$this->add_section( __( 'White Label', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'white-label'


/**
 * Used by premium version to add the right fields. Developpers: don't use it ;)
 *
 * @since 1.0
 */
do_action( 'premium.module.white-label' );

if ( ! has_action( 'premium.module.white-label' ) ) :

	$this->set_section_save_button( false );

	$this->add_field(
		__( 'Premium Upgrade', 'secupress' ),
		array(
			'name'        => $plugin . '_need_premium',
			'field_type'  => 'field_button',
		),
		array(
			'button' => array(
				'button_label' => __( 'Premium Upgrade', 'secupress' ),
				'url'          => '#', ////
			),
			'helper_help' => array(
				'name'         => 'need_premium',
				'description'  => __( 'This feature is only available in the <strong>Premium Version</strong>.', 'secupress' )
			),
		)
	);

endif;
