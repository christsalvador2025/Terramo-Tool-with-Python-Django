# your_app/management/commands/import_esg_questions.py
from django.core.management.base import BaseCommand
from django.db import transaction
import pandas as pd
import json
import csv
from core_apps.esg.models import ESGQuestion, ESGCategory, ESGYear

class Command(BaseCommand):
    help = 'Import ESG questions from Excel, CSV, or JSON file'

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help='Path to the data file')
        parser.add_argument('--year', type=int, help='ESG Year (default: current year)', default=None)
        parser.add_argument('--format', type=str, choices=['excel', 'csv', 'json'], 
                          help='File format (auto-detected if not specified)')
        parser.add_argument('--sheet', type=str, help='Excel sheet name (default: first sheet)', default=0)
        parser.add_argument('--clear', action='store_true', help='Clear existing questions for the year')

    def handle(self, *args, **options):
        file_path = options['file_path']
        year_value = options.get('year')
        file_format = options.get('format')
        sheet_name = options.get('sheet')
        clear_existing = options.get('clear', False)
        
        try:
            # Get or create ESG Year
            if year_value:
                esg_year, created = ESGYear.objects.get_or_create(
                    year=year_value,
                    defaults={'is_active': True}
                )
                if created:
                    self.stdout.write(f'Created new ESG year: {year_value}')
            else:
                esg_year = ESGYear.get_current_year()
                if not esg_year:
                    self.stdout.write(
                        self.style.ERROR('No current ESG year found. Please specify --year')
                    )
                    return
            
            self.stdout.write(f'Using ESG year: {esg_year.year}')
            
            # Clear existing questions if requested
            if clear_existing:
                deleted_count = ESGQuestion.objects.filter(year=esg_year).count()
                ESGQuestion.objects.filter(year=esg_year).delete()
                self.stdout.write(f'Cleared {deleted_count} existing questions for {esg_year.year}')
            
            with transaction.atomic():
                if file_path.endswith('.xlsx') or file_format == 'excel':
                    self.import_from_excel(file_path, esg_year, sheet_name)
                elif file_path.endswith('.csv') or file_format == 'csv':
                    self.import_from_csv(file_path, esg_year)
                elif file_path.endswith('.json') or file_format == 'json':
                    self.import_from_json(file_path, esg_year)
                else:
                    self.stdout.write(
                        self.style.ERROR('Unsupported file format. Use .xlsx, .csv, or .json')
                    )
                    return
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully imported ESG questions for {esg_year.year}!')
            )
        
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error importing data: {str(e)}')
            )

    def import_from_excel(self, file_path, esg_year, sheet_name):
        """Import from Excel file"""
        try:
            df = pd.read_excel(file_path, sheet_name=sheet_name)
        except Exception as e:
            raise Exception(f"Error reading Excel file: {str(e)}")
        
        self.process_dataframe(df, esg_year)

    def import_from_csv(self, file_path, esg_year):
        """Import from CSV file"""
        try:
            df = pd.read_csv(file_path)
        except Exception as e:
            raise Exception(f"Error reading CSV file: {str(e)}")
        
        self.process_dataframe(df, esg_year)

    def import_from_json(self, file_path, esg_year):
        """Import from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            questions = []
            for item in data:
                category = self.get_or_create_category(
                    item.get('category_name'),
                    item.get('category_display_name'),
                    item.get('category_description')
                )
                
                questions.append(ESGQuestion(
                    category=category,
                    measure=item['measure'],
                    index_code=item['index_code'],
                    desription=item.get('description', ''),
                    order=item.get('order', 0),
                    year=esg_year,
                    is_active=item.get('is_active', True)
                ))
            
            ESGQuestion.objects.bulk_create(questions, batch_size=100)
            self.stdout.write(f'Imported {len(questions)} questions from JSON')
            
        except Exception as e:
            raise Exception(f"Error processing JSON file: {str(e)}")

    def process_dataframe(self, df, esg_year):
        """Process pandas DataFrame and create ESG questions"""
        # Clean column names (remove spaces, make lowercase)
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
        
        # Check required columns
        required_columns = ['category_name', 'measure', 'index_code']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            raise Exception(f"Missing required columns: {missing_columns}")
        
        questions = []
        created_categories = set()
        
        for index, row in df.iterrows():
            try:
                # Skip empty rows
                if pd.isna(row.get('measure')) or pd.isna(row.get('index_code')):
                    continue
                
                # Get or create category
                category = self.get_or_create_category(
                    row['category_name'],
                    row.get('category_display_name', row['category_name']),
                    row.get('category_description', '')
                )
                
                if category.name not in created_categories:
                    self.stdout.write(f'Using category: {category.display_name}')
                    created_categories.add(category.name)
                
                # Create question object
                question = ESGQuestion(
                    category=category,
                    measure=str(row['measure']).strip(),
                    index_code=str(row['index_code']).strip().upper(),
                    desription=str(row.get('description', '')).strip() if pd.notna(row.get('description')) else '',
                    order=int(row.get('order', 0)) if pd.notna(row.get('order')) else 0,
                    year=esg_year,
                    is_active=bool(row.get('is_active', True))
                )
                
                questions.append(question)
                
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(f'Error processing row {index + 2}: {str(e)}')
                )
                continue
        
        if questions:
            # Use bulk_create with ignore_conflicts to avoid duplicates
            try:
                ESGQuestion.objects.bulk_create(questions, batch_size=100, ignore_conflicts=True)
                self.stdout.write(f'Successfully imported {len(questions)} ESG questions')
            except Exception as e:
                # If bulk_create fails, try individual creation
                self.stdout.write(f'Bulk create failed, trying individual creation: {str(e)}')
                created_count = 0
                for question in questions:
                    try:
                        ESGQuestion.objects.get_or_create(
                            category=question.category,
                            index_code=question.index_code,
                            year=question.year,
                            defaults={
                                'measure': question.measure,
                                'desription': question.desription,
                                'order': question.order,
                                'is_active': question.is_active
                            }
                        )
                        created_count += 1
                    except Exception as individual_error:
                        self.stdout.write(
                            self.style.WARNING(f'Failed to create question {question.index_code}: {individual_error}')
                        )
                
                self.stdout.write(f'Created {created_count} questions individually')
        else:
            self.stdout.write(self.style.WARNING('No valid questions found in the file'))

    def get_or_create_category(self, name, display_name=None, description=None):
        """Get or create ESG category"""
        if not name:
            raise Exception("Category name is required")
        
        name = str(name).strip()
        display_name = display_name or name
        description = description or ''
        
        category, created = ESGCategory.objects.get_or_create(
            name=name,
            defaults={
                'display_name': display_name,
                'description': description,
                'is_active': True
            }
        )
        
        if created:
            self.stdout.write(f'Created new category: {display_name}')
        
        return category