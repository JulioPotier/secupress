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

$plugin_path = 'sf-author-url-control/sf-author-url-control.php';
$plugin_page = 'options-permalink.php#author_base';
if ( secupress_is_plugin_active( $plugin_path ) ) { // Grégory Viguier first ;)
	$this->add_field( array(
		'title'        => __( 'Author Page Base', 'secupress' ),
		'description'  => __( 'If your site allows, it may display author pages; here, you can change the base page. Users with access to their WordPress profile page can choose their own slug.', 'secupress' ),
		'type'         => 'text',
		'label_before' => home_url( ! is_multisite() ? '/' : '/blog/' ),
		'label_after'  => '/&hellip;',
		'value'        => sf_auc_get_author_base(),
		'disabled'     => true,
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => secupress_plugin_in_usage_string( $plugin_path, $plugin_page ),
			),
		),
	) );
} else {
	$this->add_field( array(
		'title'        => __( 'Author Page Base', 'secupress' ),
		'description'  => __( 'If your site allows, it may display author pages; here, you can change the base page. Users with access to their WordPress profile page can choose their own slug.', 'secupress' ),
		'name'         => $this->get_field_name( 'author_base' ),
		'type'         => 'text',
		'label_before' => home_url( ! is_multisite() ? '/' : '/blog/' ),
		'label_after'  => '/&hellip;',
		'value'        => secupress_get_author_base()
	) );
}