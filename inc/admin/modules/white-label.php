<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


$this->set_current_section( 'secupress_display_white_label' );
$this->set_section_description( __( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated.', 'secupress' ) );
$this->add_section( __( 'White Label', 'secupress' ), array( 'with_save_button' => false ) );


/**
 * Used by pro version to add the right fields. Developpers: don't use it ;)
 *
 * @since 1.0
 */
do_action( 'secupress.pro.module.white-label' );

if ( ! has_action( 'secupress.pro.module.white-label' ) ) :

	$this->add_field( array(
		'title'        => __( 'Premium Upgrade', 'secupress' ),
		'name'         => $this->get_field_name( 'need_premium' ),
		'field_type'   => 'field_button',
		'label'        => __( 'Premium Upgrade', 'secupress' ),
		'url'          => '#', ////
		'helpers'      => array(
			array(
				'type'         => 'help',
				'description'  => __( 'This feature is only available in the <strong>Premium Version</strong>.', 'secupress' ),
			),
		),
	) );

endif;
