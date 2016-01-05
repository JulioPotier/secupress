<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-storage' );
$this->add_section( __( 'Backups Storage', 'secupress' ), array( 'with_save_button' => false ) );


$field_name = $this->get_field_name( 'location' );

$this->add_field( array(
	'title'        => __( 'Storage Location', 'secupress' ),
	'description'  => __( 'Where do you want to store you backups?', 'secupress' ),
	'label_for'    => $field_name,
	'type'         => 'radios',
	'default'      => 'local',
	'label_screen' => __( 'Storage Location', 'secupress' ),
	'options'      => array(
		'local'     => __( 'Local', 'secupress' ),
		'ftp'       => __( 'FTP', 'secupress' ),
		'amazons3'  => __( 'Amazon S3', 'secupress' ),
		'dropbox'   => __( 'Dropbox', 'secupress' ),
		'rackspace' => __( 'Rackspace Cloud', 'secupress' ),
	),
	'helpers' => array(
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'Will be stored in %sPlease, delete them as soon as possible.', 'secupress' ), '<code>' . str_replace( ABSPATH, '', secupress_get_backup_path() ) . '</code>' ),
			'depends'     => $field_name . '_local',
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'Your FTP constants present in your %1$s file will be used, so, you have to fill this first.<br/><a href="%2$s" target="_blank">Need help do to it?</a>', 'secupress' ), '<code>wp-config.php</code>', '#' ), ////
			'depends'     => $field_name . '_ftp',
		),
	),
) );
