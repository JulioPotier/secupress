<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


$this->set_current_section( 'secupress_auto-config' );
$this->set_section_description( __( 'You can trust in our auto setting configuration. Depending on your needs, just select and save, we will handle this for you.', 'secupress' ) );
$this->add_section( __( 'Auto configuration <strong><em>(optional)</em></strong>', 'secupress' ) );


$this->add_field(
	__( 'Level of configuration', 'secupress' ),
	array(
		'name'        => $this->get_field_name( 'level' ),
	),
	array(
		array(
			'type'         => 'radio',
			// 4 = high ; 3 = default ; 2 = low ; 1 = guess :)
			'options'      => array(
				4 => __( '<strong>High level</strong> This is a very restrictive configuration, you could need it when you think you are under attack.', 'secupress' ),
				3 => __( '<strong>Default level</strong> This configuration is the one we used when you activated the plugin.', 'secupress' ),
				2 => __( '<strong>Low level</strong> We will just protect the minimum things a website can need avoiding to be blocking.', 'secupress' ),
				1 => __( '<strong>Custom</strong> Your own settings!', 'secupress' ),
			),
			'default'      => 3,
			'label_for'    => 'auto_config_level',
			'label_screen' => __( 'Auto configuration', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => 'auto_config_level',
			/* Translators: %s is "little video". */
			'description'  => sprintf( __( 'Still hesitating? Watch this %s, it will help you decide.', 'secupress' ), '<a href="#">' . __( 'little video', 'secupress' ) . '</a>' ),
		),
	)
);
