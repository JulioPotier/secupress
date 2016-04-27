<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_nginx;

// Add the form manually since i just need it for this block.
add_action( 'before_section_backups-storage', array( $this, 'print_open_form_tag' ) );
add_action( 'after_section_backups-storage', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'backups-storage' );
$this->add_section( __( 'Backups Storage', 'secupress' ), array( 'with_save_button' => true ) );

$backups_dir = WP_CONTENT_DIR . '/backups/';
$backup_dir  = secupress_get_hashed_folder_name( 'backup', $backups_dir );
$backup_dir  = str_replace( rtrim( wp_normalize_path( ABSPATH ), '/' ), '', wp_normalize_path( $backup_dir ) );

if ( $is_nginx ) {
	$path  = secupress_get_rewrite_bases();
	$path  = $path['home_from'] . rtrim( dirname( $backup_dir ), '/' );
	$rules = "
server {
	location ~* $path {
		deny all;
	}
}";
}

$field_name = $this->get_field_name( 'location' );

$this->add_field( array(
	'title'        => __( 'Storage Location', 'secupress' ),
	'description'  => __( 'Where do you want to store you backups?', 'secupress' ),
	'name'         => $field_name,
	'type'         => 'radios',
	'value'        => secupress_is_pro() ? null : 'local',
	'default'      => 'local',
	'label_screen' => __( 'Storage Location', 'secupress' ),
	'options'      => secupress_backups_storage_labels(),
	'helpers' => array(
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'Will be stored in %s. Please, delete them as soon as possible.', 'secupress' ), '<code>' . $backup_dir . '</code>' ),
			'depends'     => $field_name . '_local',
		),
		array(
			'type'        => 'warning',
			'description' => $is_nginx ? sprintf( __( 'Please, add the following rules to your %1$s file: %2$s.', 'secupress' ), '<code>nginx.conf</code>', '<pre>' . $rules . '</pre>' ) : '',
			'depends'     => $field_name . '_local',
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'Your FTP constants present in your %1$s file will be used, so, you have to fill this first.<br/><a href="%2$s" target="_blank">Need help do to it?</a>', 'secupress' ), '<code>wp-config.php</code>', '#' ), // ////.
			'depends'     => $field_name . '_ftp',
		),
	),
) );
