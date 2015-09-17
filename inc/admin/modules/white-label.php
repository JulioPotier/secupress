<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_settings_section( 'secupress_display_white_label', __( 'White Label', 'secupress' ), '__secupress_whitelabel_info', 'secupress_white-label' );

add_settings_field(
	'secupress_plugin_name',
	__( 'Plugin Name', 'secupress' ),
	'secupress_field',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		array(
			'type'         => 'text',
			'label'        => '',
			'default'      => SECUPRESS_PLUGIN_NAME,
			'label_for'    => 'plugin_name',
			'label_screen' => __( 'Plugin Name', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_plugin_uri',
	__( 'Plugin URI', 'secupress' ),
	'secupress_field',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		array(
			'type'         => 'text',
			'label'        => '',
			'default'      => 'http://secupress.me',
			'label_for'    => 'plugin_uri',
			'label_screen' => __( 'Plugin UTI', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_plugin_desc',
	__( 'Description', 'secupress' ),
	'secupress_field',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		array(
			'type'         => 'textarea',
			'label'        => '',
			'default'      => 'The best and easier way to protect all your websites.',
			'label_for'    => 'plugin_desc',
			'label_screen' => __( 'Description', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_plugin_author',
	__( 'Author', 'secupress' ),
	'secupress_field',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		array(
			'type'         => 'text',
			'label'        => '',
			'default'      => 'SecuPress',
			'label_for'    => 'plugin_author',
			'label_screen' => __( 'Author', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_plugin_author_uri',
	__( 'Author URI', 'secupress' ),
	'secupress_field',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		array(
			'type'         => 'text',
			'label'        => '',
			'default'      => 'http://secupress.me',
			'label_for'    => 'plugin_author_uri',
			'label_screen' => __( 'Author URI', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_plugin_reset',
	'',
	'secupress_button',
	'secupress_white-label',
	'secupress_display_white_label',
	array(
		'button' =>
		array(
			'button_label' => __( 'Reset White Label values to default', 'secupress' ),
			'url'   => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_resetwl' ), 'secupress_resetwl' ), //// todo secupress_resetwl admin-post
		),
		'helper_warning' =>
		array(
			'name'			=> 'reset_default',
			'description'	=> __( ' If you change anything, the tutorial + FAQ + Support tabs will be hidden.', 'secupress' )
		),
	)
);

function __secupress_whitelabel_info() {
	_e( 'You can change the name of the plugin, this will be shown on the plugins page, only when activated.', 'secupress' );
	echo '<hr>';
}