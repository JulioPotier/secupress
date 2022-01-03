<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Insert content at the beginning of web.config file.
 * Can also be sused to remove content.
 *
 * @since 1.0
 *
 * @param (string) $marker An additional suffix string to add to the "SecuPress" marker.
 * @param (array)  $args   An array containing the following arguments:
 *                         (array|string) $nodes_string Content to insert in the file.
 *                         (array|string) $node_types   Node types: used to removed old nodes. Optional.
 *                         (string)       $path         Path where nodes should be created, relative to `/configuration/system.webServer`.
 *
 * @return (bool) true on success.
 */
function secupress_insert_iis7_nodes( $marker, $args = array() ) {
	static $web_config_file;

	$args = wp_parse_args( $args, array(
		'nodes_string' => '',
		'node_types'   => false,
		'path'         => '',
		'attribute'    => 'name',
	) );

	$nodes_string = $args['nodes_string'];
	$node_types   = $args['node_types'];
	$path         = $args['path'];
	$attribute    = $args['attribute'];

	if ( ! $marker || ! class_exists( 'DOMDocument' ) ) {
		return false;
	}

	if ( ! isset( $web_config_file ) ) {
		$web_config_file = secupress_get_home_path() . 'web.config';
	}

	// New content.
	$marker       = strpos( $marker, 'SecuPress' ) === 0 ? $marker : 'SecuPress ' . $marker;
	$nodes_string = is_array( $nodes_string ) ? implode( "\n", $nodes_string ) : $nodes_string;
	$nodes_string = trim( $nodes_string, "\r\n\t " );

	if ( ! secupress_root_file_is_writable( 'web.config' ) || ! $nodes_string ) {
		return false;
	}

	$filesystem = secupress_get_filesystem();

	// If configuration file does not exist then we create one.
	if ( ! $filesystem->exists( $web_config_file ) ) {
		$filesystem->put_contents( $web_config_file, '<configuration/>' );
	}

	$doc = new DOMDocument();
	$doc->preserveWhiteSpace = false;

	if ( false === $doc->load( $web_config_file ) ) {
		return false;
	}

	$path_end = ! $path && strpos( ltrim( $nodes_string ), '<rule ' ) === 0 ? '/rewrite/rules' : '';
	$path     = '/configuration/system.webServer' . ( $path ? '/' . trim( $path, '/' ) : '' ) . $path_end;

	$xpath = new DOMXPath( $doc );

	// Remove possible nodes not created by us.
	if ( $node_types ) {
		$node_types = (array) $node_types;

		foreach ( $node_types as $node_type ) {
			$old_nodes = $xpath->query( $path . '/' . $node_type );

			if ( $old_nodes->length > 0 ) {
				foreach ( $old_nodes as $old_node ) {
					$old_node->parentNode->removeChild( $old_node );
				}
			}
		}
	}

	// Remove old nodes created by us.
	$old_nodes = $xpath->query( "$path/*[starts-with(@$attribute,'$marker')]" );

	if ( $old_nodes->length > 0 ) {
		foreach ( $old_nodes as $old_node ) {
			$old_node->parentNode->removeChild( $old_node );
		}
	}

	// No new nodes? Stop here.
	if ( ! $nodes_string ) {
		$doc->formatOutput = true;
		saveDomDocument( $doc, $web_config_file );
		return true;
	}

	// Indentation.
	$spaces = explode( '/', trim( $path, '/' ) );
	$spaces = count( $spaces ) - 1;
	$spaces = str_repeat( ' ', $spaces * 2 );

	// Create fragment.
	$fragment = $doc->createDocumentFragment();
	$fragment->appendXML( "\n$spaces  $nodes_string\n$spaces" );

	// Maybe create child nodes and then, prepend new nodes.
	secupress_get_iis7_node( $doc, $xpath, $path, $fragment );

	// Save and finish.
	$doc->encoding     = 'UTF-8';
	$doc->formatOutput = true;
	saveDomDocument( $doc, $web_config_file );

	return true;
}


/**
 * Get a DOMNode node.
 * If it does not exist it is created recursively.
 *
 * @since 1.0
 *
 * @param (object) $doc   DOMDocument element.
 * @param (object) $xpath DOMXPath element.
 * @param (string) $path  Path to the desired node.
 * @param (object) $child DOMNode to be prepended.
 *
 * @return (object) The DOMNode node.
 */
function secupress_get_iis7_node( $doc, $xpath, $path, $child ) {
	$nodelist = $xpath->query( $path );

	if ( $nodelist->length > 0 ) {
		return secupress_prepend_iis7_node( $nodelist->item( 0 ), $child );
	}

	$path = explode( '/', $path );
	$node = array_pop( $path );
	$path = implode( '/', $path );

	$final_node = $doc->createElement( $node );

	if ( $child ) {
		$final_node->appendChild( $child );
	}

	return secupress_get_iis7_node( $doc, $xpath, $path, $final_node );
}


/**
 * A shorthand to prepend a DOMNode node.
 *
 * @since 1.0
 *
 * @param (object) $container_node DOMNode that will contain the new node.
 * @param (object) $new_node       DOMNode to be prepended.
 *
 * @return (object) DOMNode containing the new node.
 */
function secupress_prepend_iis7_node( $container_node, $new_node ) {
	if ( ! $new_node ) {
		return $container_node;
	}

	if ( $container_node->hasChildNodes() ) {
		$container_node->insertBefore( $new_node, $container_node->firstChild );
	} else {
		$container_node->appendChild( $new_node );
	}

	return $container_node;
}
