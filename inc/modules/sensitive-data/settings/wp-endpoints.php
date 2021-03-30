<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'wp_endpoints' );
$this->add_section( __( 'WordPress Endpoints', 'secupress' ) );


$this->add_field( array(
	'title'        => __( 'XML-RPC', 'secupress' ),
	'description'  => __( 'If you don’t use XML-RPC, you can disable it and avoid becoming a target if a vulnerability is discovered.', 'secupress' ),
	'name'         => $this->get_field_name( 'xmlrpc' ),
	'type'         => 'radioboxes',
	'value'        => ( secupress_is_submodule_active( 'sensitive-data', 'xmlrpc' ) ? null : array() ),
	'options'      => array(
		'block-all'   => __( '<strong>Disable all</strong> the features of XML-RPC', 'secupress' ),
		'block-multi' => __( '<strong>Only disable</strong> for multiple authentication attempts', 'secupress' ),
	),
	'helpers'      => array(
		array(
			'type'        => 'warning',
			'description' => __( 'If you have a mobile application, or any service linked to your website, you should not disable all the features of XML-RPC.', 'secupress' ),
		),
	),
) );
