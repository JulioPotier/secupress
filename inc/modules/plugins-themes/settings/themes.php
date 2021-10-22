<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions for your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	'title'             => __( 'Theme installation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'installation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-installation' ),
	'label'             => __( 'Yes, disable the installation for themes', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Disable theme upload.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Theme switch', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-activation' ),
	'label'             => __( 'Yes, disable switch theme', 'secupress' ),
) );


$this->add_field( array(
	'title'             => __( 'Theme deletion', 'secupress' ),
	'label_for'         => $this->get_field_name( 'deletion' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-deletion' ),
	'label'             => __( 'Yes, disable deletion of themes', 'secupress' ),
) );


$main_field_name = $this->get_field_name( 'detect_bad_themes' );

$this->add_field( array(
	'title'             => __( 'Detect Bad Themes', 'secupress' ),
	'description'       => __( 'Work for any public theme, premium or free.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ),
	'label'             => __( 'Yes, enable the detection of themes with known vulnerabilites', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => sprintf( __( 'Based on %s Daily Security Monitoring, notices will be displayed for plugins newly detected as vulnerable.', 'secupress' ),
								'<a href="https://patchstack.com/database/" target="_blank">Patchstack.com</a>'
				 			),
		),
	),
) );

$lastupdate = secupress_get_option( 'bad_themes_last_update', 0 );
$lastupdate = 0 !== $lastupdate ? $lastupdate : __( 'Not yet', 'secupress' );
$this->add_field( array(
	'title'        => __( 'Manual Update', 'secupress' ),
	'label_for'    => 'themes_manual_update',
	'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? $main_field_name : 'not_installed_yet',
	'type'         => 'html',
	'value'        => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_bad_themes_update_data' ), 'secupress_bad_themes_update_data' ) . '" class="button button-secondary">' . __( 'Update the data', 'secupress' ) . '</a>' : '<a disabled class="button button-secondary">' . __( 'Save changes first', 'secupress' ) . '</a>',
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => sprintf( __( 'The Patchstack database will update twice a day automatically. But you can still update it manually.<br>Last update: %s', 'secupress' ), $lastupdate ),
		),
	),
) );
