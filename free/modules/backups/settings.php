<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->load_plugin_settings( 'backups-storage' );
$this->load_plugin_settings( 'backup-history' );
$this->load_plugin_settings( 'backup-db' );
$this->load_plugin_settings( 'backup-files' );
