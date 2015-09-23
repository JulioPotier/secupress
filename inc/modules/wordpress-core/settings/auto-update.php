<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'wordpress_updates' );
$this->add_section( __( 'WordPress Updates', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'auto_update'


$this->add_field(
	__( 'Minor Updates', 'secupress' ),
	array(
		'name'        => $plugin . '_minor',
		'description' => __( 'Let WordPress updates itself when a minor version is available.<br>4.3.<b>1</b> is a minor version.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $plugin . '_minor',
			'label'        => __( 'Try to force WordPress to allow auto updates for <b>minor</b> versions.', 'secupress' ),
			'label_for'    => $plugin . '_minor',
			'label_screen' => __( 'Allow minor versions updates', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => 'plugin_' . $plugin,
			'description'  => __( 'Not allowing this may result using a vulnerable version of WordPress. Usually, minor versions are safe to update and contains security fixes.', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'Major Updates', 'secupress' ),
	array(
		'name'        => $plugin . '_major',
		'description' => __( 'Let WordPress updates itself when a major version is available.<br>4.<b>4</b> is a major version.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $plugin . '_major',
			'label'        => __( 'Try to force WordPress to allow auto updates for <b>major</b> versions.', 'secupress' ),
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Allow major versions updates', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => $plugin . '_major',
			'description'  => __( 'This is not mandatory but recommanded since a major version also contains security fixes.', 'secupress' ),
		),
	)
);
