<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions for your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	'title'             => __( 'Theme Actions', 'secupress' ),
	'label_for'         => $this->get_field_name( 'actions' ),
	'description'       => __( 'This will disallow <strong>installation, activation, deactivation, deletion</strong> on this site.', 'secupress' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-installation' ),
	'label'             => __( 'Yes, disable <strong>all actions</strong> for every themes', 'secupress' ),
) );

$main_field_name = $this->get_field_name( 'detect_bad_themes' );

$this->add_field( array(
	'title'             => __( 'Monitor Vulnerable Themes', 'secupress' ),
	'description'       => sprintf( __( 'Based on %s Daily Security Monitoring, notices will be displayed for newly detected vulnerable themes.', 'secupress' ),
							'<a href="https://patchstack.com/database/" target="_blank" rel="noopener" rel="noreferer">Patchstack.com</a>'
						),
	'plugin_activation' => true,
	'label_for'         => $main_field_name,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ),
	'label'             => __( 'Yes, enable detection of themes with known vulnerabilities', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Compatible with any public theme, whether premium or free.', 'secupress' ),
		),
	),
) );

$lastupdate = secupress_get_option( 'bad_themes_last_update', 0 );
$lastupdate = 0 !== $lastupdate ? $lastupdate : __( 'Not yet', 'secupress' );
if ( secupress_is_expert_mode() ) {
	$this->add_field( array(
		'title'        => __( 'Last Update', 'secupress' ),
		'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? $main_field_name : 'not_installed_yet',
		'type'         => 'html',
		'label_for'    => 'themes_last_update',
		'value'        => $lastupdate,
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => __( 'The Patchstack database updates automatically once a day', 'secupress' ),
			),
		),
	) );
} else {
	$this->add_field( array(
		'title'        => __( 'Manual Update', 'secupress' ),
		'label_for'    => 'themes_manual_update',
		'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? $main_field_name : 'not_installed_yet',
		'type'         => 'html',
		'value'        => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_bad_themes_update_data' ), 'secupress_bad_themes_update_data' ) . '" class="button button-secondary">' . __( 'Update the data', 'secupress' ) . '</a>' : '<a disabled class="button button-secondary">' . __( 'Save changes first', 'secupress' ) . '</a>',
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => sprintf( __( 'The Patchstack database updates automatically once a day, but you can also update it manually if needed.<br>Last update: %s', 'secupress' ), $lastupdate ),
			),
		),
	) );
}

$this->add_field( array(
	'depends'           => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ) ? $main_field_name : 'not_installed_yet',
	'description'       => __( 'Display a banner if a theme has not been updated since 2 years, or has been removed from the official WordPress repository.', 'secupress' ),
	'type'              => 'checkbox',
	'disabled'          => true,
	'readonly'          => true,
	'value'             => true,
	'label'             => __( 'Yes, check not maintained or closed themes too.', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Only compatible with any public theme from wp.org. Cannot be unchecked.', 'secupress' ),
		),
	),
) );
