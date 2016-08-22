<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->add_section( __( 'Services', 'secupress' ), array( 'with_save_button' => false ) );

$this->add_field( array(
	'title'        => __( 'Professional Configuration', 'secupress' ),
	'description'  => __( 'You may need help to configure the plugin perfectly, we might do this for you for $200.', 'secupress' ),
	'name'         => $this->get_field_name( 'proconfig' ),
	'field_type'   => 'field_button',
	'disabled'     => true,
	// 'label'        => __( 'Request a Professional Configuration', 'secupress' ), ////
	// 'url'          => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_pro_config' ), 'secupress_get_pro_config' ), ////
	'label'        => __( 'Coming Soon', 'secupress' ),
) );

$this->add_field( array(
	'title'        => __( 'Your website has been hacked?', 'secupress' ),
	'description'  => __( 'We may help you to recover your website after a cleansing, we charge $500.', 'secupress' ),
	'name'         => $this->get_field_name( 'got-hacked' ),
	'field_type'   => 'field_button',
	'disabled'     => true,
	// 'label'        => __( 'Request a Website cleansing', 'secupress' ), ////
	// 'url'          => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_hacked' ), 'secupress_get_hacked' ), ////
	'label'        => __( 'Coming Soon', 'secupress' ),
) );
