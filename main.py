import argparse
import sys
import os
from oradad_extractor import OradadExtractor, OradadParsingError
from oradad_reporter import OradadReporter
from oradad_visualizer import OradadVisualizer
from schema_analyzer import SchemaAnalyzer

def validate_file(file_path: str) -> bool:
    """Validate input file"""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist", file=sys.stderr)
        return False
    
    if not file_path.lower().endswith('.mla'):
        print(f"Warning: File '{file_path}' does not have .mla extension", file=sys.stderr)
        response = input("Continue anyway? (y/N): ")
        return response.lower() == 'y'
    
    return True

def main():
    parser = argparse.ArgumentParser(description='ORADAD MLA File Analyzer')
    parser.add_argument('input_file', help='Path to .mla file')
    parser.add_argument('--output', '-o', help='Output file for report (optional)')
    parser.add_argument('--format', 
                       choices=['txt', 'json', 'html', 'csv', 'forest', 'schema'],
                       default='html',
                       help='Output format (default: html)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--domain', help='Specific domain for OU tree visualization')
    
    args = parser.parse_args()
    
    if not validate_file(args.input_file):
        sys.exit(1)
    
    try:
        logger = setup_logging(verbose=args.verbose)
        logger.info(f"Parsing file: {args.input_file}")
        
        extractor = OradadExtractor(args.input_file, logger)
        extractor.parse_file()
        
        if args.format == 'forest':
            visualizer = OradadVisualizer(extractor)
            output_file = args.output or 'forest.html'
            visualizer.generate_forest_visualization(output_file)
            if args.domain:
                ou_file = f'ou_tree_{args.domain}.html'
                visualizer.generate_ou_tree(args.domain, ou_file)
        elif args.format == 'schema':
            analyzer = SchemaAnalyzer(extractor)
            report = analyzer.generate_schema_report()
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
            else:
                print(report)
        else:
            reporter = OradadReporter(extractor)
            
            if args.format == 'txt':
                report = reporter.generate_text_report()
            elif args.format == 'json':
                report = reporter.generate_json_report()
            elif args.format == 'csv':
                if not args.output:
                    print("Error: CSV format requires an output directory", file=sys.stderr)
                    sys.exit(1)
                reporter.export_to_csv(args.output)
                print(f"CSV reports exported to: {args.output}")
                return
            else:
                report = reporter.generate_html_report()
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
                if args.verbose:
                    print(f"Report written to: {args.output}")
            else:
                print(report)
            
    except OradadParsingError as e:
        print(f"Error parsing file: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()