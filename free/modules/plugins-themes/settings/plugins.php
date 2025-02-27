<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'plugins_themes' );
$this->set_section_description( __( 'By using these protections, you can easily specify the permitted actions for your plugins.', 'secupress' ) );
$this->add_section( __( 'Plugins Page', 'secupress' ) );

$req_wp_ver  = '6.3'; // 6.3 because of the needed filter "plugins_list"
$is_wp_ok    = secupress_wp_version_is( $req_wp_ver );
$helper_type = '';
$helper_desc = '';
if ( ! $is_wp_ok ) {
	$helper_type = 'warning';
	$helper_desc = sprintf( __( 'WordPress <b>v%1$s</b> is required to use the module <em>%2$s</em>.', 'secupress' ), $req_wp_ver, __( 'Plugin Actions', 'secupress' ) );
}

$this->add_field( array(
	'title'             => __( 'Plugin Actions', 'secupress' ),
	'label_for'         => $this->get_field_name( 'actions' ),
	'description'       => __( 'This will disallow <strong>installation, activation, deactivation, deletion</strong> on this site.', 'secupress' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-installation' ),
	'label'             => __( 'Yes, disable <strong>all actions</strong> for every plugins', 'secupress' ),
) );

$plugins         = get_plugins();
$c_plugins       = count( $plugins );
if ( ! is_multisite() ) {
	$c_active_p  = count( array_filter( array_keys( $plugins ), 'is_plugin_active' ) );
	if ( $c_plugins === $c_active_p ) {
		$message = sprintf( __( 'I confirm this site is using <strong>%d</strong> legitimate plugins, all are activated.', 'secupress' ), $c_plugins );
	} else {
		$message = sprintf( _n( 'I confirm this site is using <strong>%1$d</strong> plugins, of which <strong>%2$d</strong> are activated and <strong>%3$d</strong> is not activated.', 'I confirm this site is using <strong>%1$d</strong> plugins, of which <strong>%2$d</strong> are activated and <strong>%3$d</strong> are not activated.', ( $c_plugins - $c_active_p ), 'secupress' ), $c_plugins, $c_active_p, ( $c_plugins - $c_active_p ) );
	}
} else {
	$c_active_p  = count( array_filter( array_keys( $plugins ), 'is_plugin_active_for_network' ) );
	if ( $c_plugins === $c_active_p ) {
		$message = sprintf( __( 'I confirm that this site is using <strong>%d</strong> legitimate plugins, all are network activated.', 'secupress' ), $c_plugins );
	} else {
		$message = sprintf( _n( 'I confirm that this site is using <strong>%1$d</strong> plugins, <strong>%2$d</strong> are network activated, <strong>%3$d</strong> is not activated.', 'I confirm that this site is using <strong>%1$d</strong> plugins, <strong>%2$d</strong> are network activated, <strong>%3$d</strong> are not activated.', ( $c_plugins - $c_active_p ), 'secupress' ), $c_plugins, $c_active_p, ( $c_plugins - $c_active_p ) );
	}
}
$muplugins       = get_mu_plugins();
$c_mup_acti      = count( $muplugins );
if ( $c_mup_acti ) {
	$message    .= ' ' . sprintf( _n( 'Additionally there is <strong>%d</strong> must-use plugin.', 'Additionally there are <strong>%d</strong> must-use plugins.', $c_mup_acti, 'secupress' ), $c_mup_acti );
}

if ( ! secupress_get_module_option( 'plugins_confirm', false, 'plugins-themes' ) ) {
	$this->add_field( array(
		'title'             => __( 'Confirmation', 'secupress' ),
		'label'             => $message,
		'label_for'         => $this->get_field_name( 'confirm' ),
		'type'              => 'checkbox',
		'depends'           => $this->get_field_name( 'actions' ),
		'helpers'           => array(
			array(
				'type'        => 'description',
				'description' => sprintf( __( 'Visit %sthe plugins page%s to check this beforehand.', 'secupress' ), '<a href="' . esc_url( network_admin_url( 'plugins.php' ) ) . '">', '</a>' ),
			),
		),
	) );
}

$this->add_field( array(
	'title'             => __( 'Display All', 'secupress' ),
	'label'             => __( 'Yes, always display all on plugins page', 'secupress' ),
	'label_for'         => $this->get_field_name( 'show-all' ),
	'type'              => 'checkbox',
	'plugin_activation' => true,
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-show-all' ),
		'helpers'           => array(
			array(
				'type'        => 'description',
				'description' => sprintf( __( 'The filters %1$s and %2$s will be emptied, CSS or JS tricks to hide them will be reverted, pagination on the plugins page will be disabled.', 'secupress' ), secupress_code_me( 'all_plugins' ), secupress_code_me( 'plugins_list' ) ),
			),
		),
) );

$this->add_field( array(
	'title'             => __( 'Highlight Color', 'secupress' ),
	'label_for'         => $this->get_field_name( 'show-all-color' ),
	'type'              => 'color',
	'depends'           => $this->get_field_name( 'show-all' ),
	'default'           => '#FAC898',
) );

$main_field_name = $this->get_field_name( 'detect_bad_plugins' );

$this->add_field( array(
	'title'             => __( 'Monitor Vulnerable Plugins', 'secupress' ),
	'description'       => sprintf( __( 'Based on %s Daily Security Monitoring, notices will be displayed for newly detected vulnerable plugins.', 'secupress' ),
							'<a href="https://patchstack.com/database/" target="_blank" rel="noopener" rel="noreferer">Patchstack.com</a>'
						),
	'plugin_activation' => true,
	'label_for'         => $main_field_name,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ),
	'label'             => __( 'Yes, enable detection of plugins with known vulnerabilities', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Compatible with any public plugin, whether premium or free.', 'secupress' ),
		),
	),
) );

$lastupdate = secupress_get_option( 'bad_plugins_last_update', 0 );
$lastupdate = 0 !== $lastupdate ? $lastupdate : __( 'Not yet', 'secupress' );
if ( ! secupress_is_expert_mode() ) {
	$this->add_field( array(
		'title'        => __( 'Last Update', 'secupress' ),
		'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ) ? $main_field_name : 'not_installed_yet',
		'type'         => 'html',
		'label_for'    => 'plugins_last_update',
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
		'label_for'    => 'plugins_manual_update',
		'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ) ? $main_field_name : 'not_installed_yet',
		'type'         => 'html',
		'value'        => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ) ? '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_bad_plugins_update_data' ), 'secupress_bad_plugins_update_data' ) . '" class="button button-secondary">' . __( 'Update the data', 'secupress' ) . '</a>' : '<a disabled class="button button-secondary">' . __( 'Save changes first', 'secupress' ) . '</a>',
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => sprintf( __( 'The Patchstack database updates automatically once a day, but you can also update it manually if needed.<br>Last update: %s', 'secupress' ), $lastupdate ),
			),
		),
	) );
}

$this->add_field( array(
	'depends'      => secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ) ? $main_field_name : 'not_installed_yet',
	'description'       => __( 'Display a banner if a plugin has not been updated since 2 years, or has been closed from the official WordPress repository.', 'secupress' ),
	'type'              => 'checkbox',
	'disabled'          => true,
	'readonly'          => true,
	'value'             => true,
	'label'             => __( 'Yes, check for not maintained and closed plugins too.', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Only compatible with any public plugin from wp.org. Cannot be unchecked.', 'secupress' ),
		),
	),
) );
