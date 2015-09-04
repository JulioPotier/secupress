<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_settings_section( 'secupress_auto_config', __( 'Auto configuration <b><i>(optional)</i></b>', 'secupress' ), '__secupress_autoconfig_info', 'secupress_autoconfig' );

add_settings_field(
	'secupress_email',
	__( 'Level of configuration', 'secupress' ),
	'secupress_field',
	'secupress_autoconfig',
	'secupress_auto_config',
	array(
		array(
			'type'         => 'radio',
			// 3 = high ; 2 = default ; 1 = low ; custom = guess :)
			'options'	   => array(	'3' => '<b>High level</b> This is a very restrictive configuration, you could need it when you think you are under attack.', 
										'2' => '<b>Default level</b> This configuration is the one we used when you activated the plugin.', 
										'1' => '<b>Low level</b> We will just protect the minimum things a website can need avoiding to be blocking.', 
										'0' => '<b>Custom</b> Your own settings!'),
			'label_for'    => 'auto_config_level',
			'label_screen' => __( 'Auto configuration', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => 'auto_config_level',
			'description'  => __( 'Still hesitating? Watch this <a href="#">little video</a>, it will help you decide.', 'secupress' )
		),
	)
);

function __secupress_autoconfig_info() {
	_e( 'You can trust in our auto setting configuration. Depending on your needs, just select and save, we will handle this for you.', 'secupress' );
	echo '<hr>';
}