<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'ssl' );
$this->set_section_description( __( 'Enforce your HTTP requests by using the secure SSL protocol for HTTPS.', 'secupress' ) );
$this->add_section( __( 'SSL Configuration', 'secupress' ) . ' — BETA' );

if ( secupress_is_https_supported() ) {
	$this->add_field( array(
		'title'             => __( 'Force HTTPS', 'secupress' ),
		'label'             => __( 'Yes, force my website to be loaded over HTTPS', 'secupress' ),
		'label_for'         => $this->get_field_name( 'force-https' ),
		'type'              => 'checkbox',
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'force-https' ),
	) );	

	$this->add_field( array(
		'title'             => __( 'Redirect every HTTP request to SSL/HTTPS', 'secupress' ),
		'label'             => sprintf( __( 'Yes, always redirect all %s requests to %s requests', 'secupress' ), '<code>HTTP</code>', '<code>SSL/HTTPS</code>' ),
		'label_for'         => $this->get_field_name( 'https-redirection' ),
		'type'              => 'checkbox',
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'https-redirection' ),
	) );

	$this->add_field( array(
		'title'             => __( 'Fix Mixed Content Warning', 'secupress' ),
		'label'             => sprintf( __( 'Yes, switch every %s in any content to %s in my website', 'secupress' ), '<code>http://</code>', '<code>https://</code>' ),
		'label_for'         => $this->get_field_name( 'mixed-content' ),
		'type'              => 'checkbox',
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'mixed-content' ),
		'helpers'           => array(
			array(
				'type'        => 'help',
				'description' => sprintf( __( '%s will NOT change anything in your content, when deactivating this feature, eveything will be back.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
		),
	) );

} else {

	$this->add_field( array(
		'title'             => __( 'Force HTTPS', 'secupress' ),
		'label'             => __( 'Yes, force my website to be loaded over HTTPS', 'secupress' ),
		'label_for'         => $this->get_field_name( 'force-https' ),
		'type'              => 'checkbox',
		'disabled'          => true,
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'force-https' ),
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => __( 'Your website does NOT support HTTPS. You cannot force HTTPS.', 'secupress' ),
			),
		),
	) );

	$this->add_field( array(
		'title'             => __( 'Redirect every HTTP request to SSL/HTTPS', 'secupress' ),
		'label'             => sprintf( __( 'Yes, always redirect all %s requests to %s requests', 'secupress' ), '<code>HTTP</code>', '<code>SSL/HTTPS</code>' ),
		'label_for'         => $this->get_field_name( 'https-redirection' ),
		'type'              => 'checkbox',
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'https-redirection' ),
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => __( 'Your website does NOT support HTTPS. You cannot redirect HTTP requests.', 'secupress' ),
			),
		),
	) );

	$this->add_field( array(
		'title'             => __( 'Fix Mixed Content Warning', 'secupress' ),
		'label'             => sprintf( __( 'Yes, switch every %s in any content to %s in my website', 'secupress' ), '<code>http://</code>', '<code>https://</code>' ),
		'label_for'         => $this->get_field_name( 'mixed-content' ),
		'type'              => 'checkbox',
		'disabled'          => true,
		'plugin_activation' => true,
		'value'             => (int) secupress_is_submodule_active( 'ssl', 'mixed-content' ),
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => __( 'Your website does NOT support HTTPS. You cannot fix mixed content.', 'secupress' ),
			),
		),
	) );
}

$this->add_field( array(
	'title'             => __( 'SSL Certificate', 'secupress' ) . ' ' . __( '(Coming soon)', 'secupress' ),
	'type'              => 'html',
	'label_for'         => $this->get_field_name( 'ssl-certificate' ),
	'disabled'          => true,
	'value'             => get_submit_button( __( 'Get a SSL Certificate', 'secupress' ), 'primary large', 'ssl-certificate', true, ['disabled' => 'disabled'] ),
) );