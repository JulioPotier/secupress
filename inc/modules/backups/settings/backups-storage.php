<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Add the form manually since i just need it for this block
add_action( 'before_section_backups-storage', array( $this, 'print_open_form_tag' ) );
add_action( 'after_section_backups-storage', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'backups-storage' );
$this->add_section( __( 'Backups Storage', 'secupress' ), array( 'with_save_button' => true ) );


$field_name = $this->get_field_name( 'location' );

$this->add_field( array(
	'title'        => __( 'Storage Location', 'secupress' ),
	'description'  => __( 'Where do you want to store you backups?', 'secupress' ),
	'name'         => $field_name,
	'type'         => 'radios',
	'default'      => 'local',
	'label_screen' => __( 'Storage Location', 'secupress' ),
	'options'      => secupress_backups_storage_labels(),
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
