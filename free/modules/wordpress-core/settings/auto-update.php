<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'wordpress_updates' );
$this->add_section( __( 'WordPress Updates', 'secupress' ) );


$plugin = $this->get_current_plugin();
$ver    = strlen( $GLOBALS['wp_version'] ) >= 5 ? $GLOBALS['wp_version'] : $GLOBALS['wp_version'] . '.1';
$this->add_field( array(
	'title'             => __( 'Minor Updates', 'secupress' ),
	'description'       => sprintf( __( 'By default, WordPress updates itself when a minor version is available. But a plugin could disable this feature: this setting will force automatic background updates regardless. <em>Example: <strong>%s</strong> is a minor version</em>.', 'secupress' ), $ver ),
	'label_for'         => $this->get_field_name( 'minor' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'wordpress-core', 'minor-updates' ),
	'label'             => __( 'Yes, try to force WordPress to allow auto updates for <strong>minor</strong> versions.', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => __( 'Not allowing this may result in using a vulnerable version of WordPress. Usually, minor versions are safe to update and contain security fixes.', 'secupress' ),
		),
	),
) );


$ver    = substr( $GLOBALS['wp_version'], 0, 3 );
$this->add_field( array(
	'title'             => __( 'Major Updates', 'secupress' ),
	'description'       => sprintf( __( 'Let WordPress update itself when a major version is available. <em>Example: <strong>%s</strong> is a major version</em>.', 'secupress' ), $ver ),
	'label_for'         => $this->get_field_name( 'major' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'wordpress-core', 'major-updates' ),
	'label'             => __( 'Yes, try to force WordPress to allow auto updates for <strong>major</strong> versions.', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => __( 'This is not mandatory but recommended since a major version may also contain security fixes.', 'secupress' ),
		),
	),
) );
