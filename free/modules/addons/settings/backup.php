<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'backup' );
$this->set_section_description( __( '<strong>BackWPup</strong> is the perfect WordPress Backup Plugin. With over 10 million downloads it is one of the most popular WordPress plugins worldwide. German engineering and 12 years in the making, over 700.000 active users speaks for itself. Save your backup wherever and whenever you want in Dropbox, S3, FTP and other services.', 'secupress' ) );
$this->add_section( '<span class="dashicons dashicons-admin-plugins"></span> BackWPup', array( 'with_save_button' => false ) );
$this->add_field( array(
	'type'                => 'plugin',
	'name'                => 'backwpup',
	'helpers'             => array(
		// 'description' => array(
		// 	'type'        => 'description',
		// 	'description' => '<span class="dashicons dashicons-star-filled"></span> ' . sprintf( __( 'Need more features for %1$s? <a href="%2$s" class="button button-small button-primary">Get %3$s on Pro Version</a>', 'secupress' ), 'BackWPup', 'https://backwpup.com', '-XX%' ),
		// ),
		'help' => array(
			'type'        => 'help',
			'description' => sprintf( __( 'This will install <strong>%s</strong> from the official WordPress repository.', 'secupress' ), 'BackWPup' ),
		),
	),
) );
