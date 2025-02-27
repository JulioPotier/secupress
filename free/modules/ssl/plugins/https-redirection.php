<?php
/**
 * Module Name: HTTPS Redirection
 * Description: Redirect every HTTP requests to HTTPS
 * Main Module: ssl
 * Author: Julio Potier
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_ssl_https_redirection_activation' );
add_action( 'secupress.plugins.activation', 'secupress_ssl_https_redirection_activation' );
/**
 * On module activation, add the define.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_ssl_https_redirection_activation() {
	$rules = call_user_func( secupress_get_function_name_by_server_type( 'secupress_ssl_https_redirection_for_' ) );

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'https_redirection',
		'title'  => __( 'HTTPS Redirection', 'secupress' ),
	) );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_ssl_https_redirection_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_ssl_https_redirection_deactivation' );
/**
 * On module deactivation, remove the rules.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_ssl_https_redirection_deactivation() {
	secupress_remove_module_rules_or_notice( 'https_redirection', __( 'HTTPS Redirection', 'secupress' ) );
}

function secupress_ssl_https_redirection_for_apache() {
	return '<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>';
}

function secupress_ssl_https_redirection_for_nginx() {
	$home_url = home_url();
	return 'server {
	listen 80;
	server_name ' . esc_url( $home_url ) . ';
	return 301 https://$host$request_uri;
}

server {
	listen 443 ssl;
	server_name example.com;

	root /var/www/html;
	index index.php index.html index.htm;

	ssl_certificate /etc/ssl/certs/example.com.crt;
	ssl_certificate_key /etc/ssl/private/example.com.key;

	location / {
		try_files $uri $uri/ /index.php?$args;
	}

	location ~ \.php$ {
		include fastcgi_params;
		fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
	}
}';

}

function secupress_ssl_https_redirection_for_iis7() {
	return '<rewrite>
	<rules>
		<rule name="WordPress" stopProcessing="true">
			<match url="^(.*)$" ignoreCase="false" />
			<conditions>
				<add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
				<add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
			</conditions>
			<action type="Rewrite" url="index.php/{R:1}" />
		</rule>
	</rules>
</rewrite>
';
}