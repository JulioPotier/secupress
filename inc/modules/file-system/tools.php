<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get file extensions that are forbidden in the uploads folder.
 *
 * @since 1.0
 * @see http://www.file-extensions.org/filetype/extension/name/dangerous-malicious-files
 *
 * @return (array)
 */
function secupress_bad_file_extensions_get_forbidden_extensions() {
	// Build a regex pattern with the allowed extensions.
	$allowed = wp_get_mime_types();
	$allowed = array_keys( $allowed );
	$allowed = implode( '|', $allowed );
	$allowed = "#,($allowed),#i";

	$exts = array(
		'.9',
		'73i87a', '386',
		'aaa', 'abc', 'aepl', 'aru', 'atm', 'aut',
		'bat', 'bhx', 'bin', 'bkd', 'blf', 'bll', 'bmw', 'boo', 'bps', 'bqf', 'breaking_bad', 'btc', 'buk', 'bup', 'bxz',
		'cc', 'ccc', 'ce0', 'ceo', 'cfxxe', 'chm', 'cih', 'cla', 'class', 'cmd', 'com', 'coverton', 'cpl', 'crinf', 'crjoker', 'crypt', 'crypted', 'cryptolocker', 'cryptowall', 'ctbl', 'cxq', 'cyw', 'czvxce',
		'darkness', 'dbd', 'delf', 'dev', 'dlb', 'dli', 'dll', 'dllx', 'dom', 'drv', 'dx', 'dxz', 'dyv', 'dyz',
		'ecc', 'enciphered', 'encrypt', 'encrypted', 'enigma', 'exe', 'exe1', 'exe_renamed', 'exx', 'ezt', 'ezz',
		'fag', 'fjl', 'fnr', 'fuj', 'fun',
		'good', 'gzquar',
		'ha3', 'hlp', 'hlw', 'hsq', 'hts',
		'iva', 'iws',
		'jar', 'js',
		'kcd', 'kernel_complete', 'kernel_pid', 'kernel_time', 'keybtc@inbox_com', 'kimcilware', 'kkk', 'kraken',
		'lechiffre', 'let', 'lik', 'lkh', 'lnk', 'locked', 'locky', 'lok', 'lol!', 'lpaq5',
		'magic', 'mfu', 'micro', 'mjg', 'mjz',
		'nls',
		'oar', 'ocx', 'osa', 'ozd',
		'p5tkjw', 'pcx', 'pdcr', 'pgm', 'php', 'php2', 'php3', 'pid', 'pif', 'plc', 'poar2w', 'pr', 'pzdc',
		'qit', 'qrn',
		'r5a', 'rdm', 'rhk', 'rna', 'rokku', 'rrk', 'rsc_tmp',
		's7p', 'scr', 'scr', 'shs', 'ska', 'smm', 'smtmp', 'sop', 'spam', 'ssy', 'surprise', 'swf', 'sys',
		'tko', 'tps', 'tsa', 'tti', 'ttt', 'txs',
		'upa', 'uzy',
		'vb', 'vba', 'vbe', 'vbs', 'vbx', 'vexe', 'vxd', 'vzr',
		'wlpginstall', 'wmf', 'ws', 'wsc', 'wsf', 'wsh', 'wss',
		'xdu', 'xir', 'xlm', 'xlv', 'xnt', 'xnxx', 'xtbl', 'xxx', 'xyz',
		'zix', 'zvz', 'zzz',
	);

	// Remove the allowed extensions from the forbidden ones.
	$exts = implode( ',', $exts );
	$exts = ",$exts,";
	$exts = preg_replace( $allowed, ',', $exts );
	$exts = trim( $exts, ',' );
	$exts = explode( ',', $exts );

	/**
	 * Filter the forbidden file extensions.
	 *
	 * @since 1.0
	 *
	 * @param (array) $all_exts The file extensions.
	 */
	$out = apply_filters( 'secupress.plugin.bad_file_extensions.forbidden_extenstions', $exts );
	$out = array_filter( $out );
	return $out ? $out : $exts;
}
