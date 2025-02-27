<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'wordpress_updates' );
$this->add_section( __( 'WordPress Updates', 'secupress' ) );


$plugin = $this->get_current_plugin();
$ver    = strlen( $GLOBALS['wp_version'] ) >= 5 ? $GLOBALS['wp_version'] : $GLOBALS['wp_version'] . '.1';
$ver    = strpos( $ver, '-' ) !== false ? substr( $ver, 0, 3 ) . '.1' : $ver;
$this->add_field( array(
	'title'             => __( 'Minor Updates', 'secupress' ),
	'description'       => sprintf( __( 'WordPress is designed to update automatically for minor versions by default. However, some plugins may disable this feature. This setting will force automatic background updates regardless. For example, <strong>%s</strong> is a minor version.', 'secupress' ), $ver ),
	'label_for'         => $this->get_field_name( 'minor' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'wordpress-core', 'minor-updates' ),
	'label'             => __( 'Yes, attempt to enable automatic updates for <strong>minor</strong> WordPress versions', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => __( 'Not enabling this may lead to using a vulnerable version of WordPress. Typically, minor versions are safe to update and include security fixes.', 'secupress' ),
		),
	),
) );


$ver    = substr( $GLOBALS['wp_version'], 0, 3 );
$this->add_field( array(
	'title'             => __( 'Major Updates', 'secupress' ),
	'description'       => sprintf( __( 'Allow WordPress to update automatically when a major version is available. <em>Example: <strong>%s</strong> is a major version</em>.', 'secupress' ), $ver ),
	'label_for'         => $this->get_field_name( 'major' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'wordpress-core', 'major-updates' ),
	'label'             => __( 'Yes, attempt to enable automatic updates for <strong>major</strong> WordPress versions', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'help',
			'description' => __( 'This is not mandatory but recommended, as major versions may also contain security fixes.', 'secupress' ),
		),
	),
) );
