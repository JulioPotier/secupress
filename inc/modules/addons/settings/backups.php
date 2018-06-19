<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backups' );

$this->add_section( __( 'Backup Add-on', 'secupress' ), array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'backwpup',
	'helpers'             => array(
		'description' => array(
			'type'        => 'description',
			'description' => __( 'Reduce the risks of losing your content in an attack by backing up your database and files.', 'secupress' ),
		),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.<br><a href="">Learn more about this add-on</a>.', 'secupress' ), 'BackWPUp' ),
		),
	),
) );
