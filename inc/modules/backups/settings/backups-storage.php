<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_apache, $is_nginx, $is_iis7;

// Add the form manually since i just need it for this block.
add_action( 'secupress.settings.before_section_backups-storage', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_backups-storage', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'backups-storage' );
$this->add_section( __( 'Backups Storage', 'secupress' ), array( 'with_save_button' => true ) );

$backups_dir = WP_CONTENT_DIR . '/backups/';
$backup_dir  = secupress_get_hashed_folder_name( 'backup', $backups_dir );
$backup_dir  = str_replace( rtrim( wp_normalize_path( ABSPATH ), '/' ), '', wp_normalize_path( $backup_dir ) );
$backups_dir = dirname( $backup_dir ) . '/';
$warning     = null;

// If we can't protect the backups folder directly with a `.htaccess` file, warn the user.
if ( ( $is_apache || $is_iis7 ) && ! secupress_pre_backup() ) {
	$file  = $is_apache ? '.htaccess' : 'web.config';
	$rules = secupress_backup_get_protection_content();
	/** Translators: 1 is a file name, 2 is a folder name, 3 is some code. */
	$warning = sprintf( __( 'Please create a %1$s file inside the folder %2$s (create the folder if does not exist), then add the following rules to it: %3$s', 'secupress' ), "<code>$file</code>", "<code>$backups_dir</code>", "<pre>$rules</pre>" );
} elseif ( $is_nginx ) {
	$rules = secupress_backup_get_protection_content();
	/** Translators: 1 is a file name, 2 is some code. */
	$warning = sprintf( __( 'Please, add the following rules to your %1$s file: %2$s.', 'secupress' ), '<code>nginx.conf</code>', "<pre>$rules</pre>" );
}

$field_name = $this->get_field_name( 'location' );

$this->add_field( array(
	'title'        => __( 'Storage Location', 'secupress' ),
	'description'  => __( 'Where do you want to store you backups?', 'secupress' ),
	'name'         => $field_name,
	'type'         => 'radios',
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
			'description' => $warning,
			'depends'     => $field_name . '_local',
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'Your FTP constants present in your %1$s file will be used, so, you have to fill this first.<br/><a href="%2$s" target="_blank">Need help do to it?</a>', 'secupress' ), '<code>wp-config.php</code>', '#' ), // ////.
			'depends'     => $field_name . '_ftp',
		),
	),
) );
