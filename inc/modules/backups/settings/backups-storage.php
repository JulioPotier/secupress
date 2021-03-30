<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'backups-storage' );
$this->add_section( __( 'Backup Storage', 'secupress' ), array( 'with_save_button' => false ) );


$warning_cant_write = null;
// The user should not keep backups locally.
$warning_local = sprintf(
	/** Translators: %s is a path to a folder. */
	__( 'Backups will be stored in %s. Please, delete them as soon as possible.', 'secupress' ),
	'<code>' . secupress_get_parent_backups_path( true ) . '</code>'
);

if ( secupress_is_pro() ) {

	// If we can't protect the backups folder directly with a `.htaccess` file, warn the user.
	if ( ! secupress_pre_backup() ) {
		if ( $is_apache ) {

			$warning_cant_write  = sprintf(
				/** Translators: %s is the path to a folder. */
				__( 'it seems some folders and a file could not be created. Please make sure to create a folder %s that contains the following:', 'secupress' ),
				'<code>' . secupress_get_parent_backups_path( true ) . '</code>'
			);
			$warning_cant_write .= '</p><ul>';
			$warning_cant_write .= '<li>';
			$warning_cant_write .= sprintf(
				/** Translators: %s is a folder name. */
				__( 'Two folders with the following names: %1$s and %2$s.', 'secupress' ),
				'<code>' . basename( secupress_get_local_backups_path() ) . '</code>',
				'<code>' . basename( secupress_get_temporary_backups_path() ) . '</code>'
			);
			$warning_cant_write .= '</li><li>';
			$warning_cant_write .= sprintf(
				/** Translators: %s is a file name. */
				__( 'A %s file containing the following rules:', 'secupress' ),
				'<code>.htaccess</code>'
			);
			$warning_cant_write .= '<pre>' . secupress_backup_get_protection_content() . '</pre>';
			$warning_cant_write .= '</li>';
			$warning_cant_write .= '</ul>';

		} elseif ( $is_iis7 ) {

			$warning_cant_write  = sprintf(
				/** Translators: 1 is a file name, 2 is the path to a folder, 3 and 4 are folder names. */
				__( 'it seems some folders could not be created and/or your %1$s file is not writable. Please make sure to create a folder %2$s that contains these two folders: %3$s and %4$s. Then add the following rules in your %1$s file:', 'secupress' ),
				'<code>web.config</code>',
				'<code>' . secupress_get_parent_backups_path( true ) . '</code>',
				'<code>' . basename( secupress_get_local_backups_path() ) . '</code>',
				'<code>' . basename( secupress_get_temporary_backups_path() ) . '</code>'
			);
			$warning_cant_write .= '</p><pre>' . secupress_backup_get_protection_content() . '</pre>';

		} elseif ( $is_nginx ) {

			$warning_cant_write  = sprintf(
				/** Translators: 1 is the path to a folder, 2 and 3 are folder names, 4 is a file name. */
				__( 'please make sure a folder %1$s has been created and it contains these two folders: %2$s and %3$s. Then add the following rules in your %4$s file:', 'secupress' ),
				'<code>' . secupress_get_parent_backups_path( true ) . '</code>',
				'<code>' . basename( secupress_get_local_backups_path() ) . '</code>',
				'<code>' . basename( secupress_get_temporary_backups_path() ) . '</code>',
				'<code>nginx.conf</code>'
			);
			$warning_cant_write .= '</p><pre>' . secupress_backup_get_protection_content() . '</pre>';

		}
	}
}

$warnings = '<div class="description warning">' . '<strong>' . __( 'Warning: ', 'secupress' ) . '</strong> ' . $warning_local . '</div>';
if ( $warning_cant_write ) {
	$warnings .= '<div class="description warning">' . '<strong>' . __( 'Warning: ', 'secupress' ) . '</strong> ' . $warning_cant_write . '</div>';
}

$this->add_field( array(
	'type'  => 'html',
	'value' => $warnings,
) );
