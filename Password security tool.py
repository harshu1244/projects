import argparse
import itertools
import string
from datetime import datetime
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from zxcvbn import zxcvbn
from nltk.corpus import words
import nltk


try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words')

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.english_words = set(words.words())
        self.leet_speak_map = {
            'a': '@4',
            'b': '8',
            'e': '3',
            'g': '96',
            'i': '1!',
            'l': '1',
            'o': '0',
            's': '$5',
            't': '7',
            'z': '2'
        }

    def _load_common_passwords(self):
        try:
            with open('common_passwords.txt', 'r') as f:
                return [line.strip() for line in f]
        except FileNotFoundError:
            return [
                'password', '123456', 'qwerty', 'admin', 'welcome',
                '12345678', 'abc123', 'password1', '12345', '123456789'
            ]

    def analyze_password(self, password):
        result = zxcvbn(password)
        analysis = {
            'password': password,
            'score': result['score'],
            'feedback': result['feedback']['warning'] if result['feedback']['warning'] else "No major weaknesses",
            'suggestions': result['feedback']['suggestions'],
            'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            'guesses': f"{result['guesses']:,}",
            'entropy': result['guesses_log10']
        }
        return analysis

class WordlistGenerator:
    def __init__(self):
        self.leet_speak_map = {
            'a': ['a', '@', '4'],
            'b': ['b', '8'],
            'e': ['e', '3'],
            'g': ['g', '9', '6'],
            'i': ['i', '1', '!'],
            'l': ['l', '1'],
            'o': ['o', '0'],
            's': ['s', '$', '5'],
            't': ['t', '7'],
            'z': ['z', '2']
        }

    def generate_wordlist(self, base_words, years=None, min_length=4, max_length=12, 
                         use_leet=True, use_upper=True, use_lower=True, 
                         use_digits=True, use_special=True):
        if years is None:
            years = []
        
        wordlist = set()
        
   
        for word in base_words:
            if not word:
                continue
                
          
            variations = [word]
            
           
            if use_upper:
                variations.append(word.upper())
            if use_lower:
                variations.append(word.lower())
            if use_upper and use_lower:
                variations.append(word.capitalize())
            
          
            if use_leet:
                leet_variations = self._generate_leet_variations(word)
                variations.extend(leet_variations)
            
       
            for variation in variations.copy():
                if use_digits:
                    for year in years:
                        variations.append(f"{variation}{year}")
                    variations.append(f"{variation}123")
                    variations.append(f"{variation}1234")
                
                if use_special:
                    variations.append(f"{variation}!")
                    variations.append(f"{variation}@")
                    variations.append(f"{variation}#")
                    variations.append(f"{variation}$")
            
       
            for variant in variations:
                if min_length <= len(variant) <= max_length:
                    wordlist.add(variant)
        
        return sorted(wordlist)

    def _generate_leet_variations(self, word):
        variations = [word]
        for i, char in enumerate(word.lower()):
            if char in self.leet_speak_map:
                new_variations = []
                for variation in variations:
                    for leet_char in self.leet_speak_map[char]:
                        new_variation = variation[:i] + leet_char + variation[i+1:]
                        new_variations.append(new_variation)
                variations.extend(new_variations)
        return variations

class PasswordToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer & Wordlist Generator")
        self.analyzer = PasswordAnalyzer()
        self.generator = WordlistGenerator()
        
        self.create_widgets()

    def create_widgets(self):
     
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)
        
 
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text='Password Analysis')
        self.setup_analysis_tab()
        
       
        self.wordlist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.wordlist_frame, text='Wordlist Generator')
        self.setup_wordlist_tab()

    def setup_analysis_tab(self):
        ttk.Label(self.analysis_frame, text="Enter Password to Analyze:").pack(pady=5)
        
        self.password_entry = ttk.Entry(self.analysis_frame, width=40, show="*")
        self.password_entry.pack(pady=5)
        
        self.show_password_var = tk.IntVar()
        ttk.Checkbutton(self.analysis_frame, text="Show Password", 
                        variable=self.show_password_var,
                        command=self.toggle_password_visibility).pack()
        
        ttk.Button(self.analysis_frame, text="Analyze Password", 
                  command=self.analyze_password).pack(pady=10)
        
        self.results_text = tk.Text(self.analysis_frame, height=15, width=60)
        self.results_text.pack(pady=10)
        
        ttk.Button(self.analysis_frame, text="Clear", 
                  command=self.clear_analysis).pack(pady=5)

    def setup_wordlist_tab(self):
        
        ttk.Label(self.wordlist_frame, text="Base Words (comma separated):").pack(pady=5)
        self.base_words_entry = ttk.Entry(self.wordlist_frame, width=50)
        self.base_words_entry.pack(pady=5)
        
     
        ttk.Label(self.wordlist_frame, text="Years to append (comma separated):").pack(pady=5)
        self.years_entry = ttk.Entry(self.wordlist_frame, width=50)
        self.years_entry.pack(pady=5)
        
       
        options_frame = ttk.Frame(self.wordlist_frame)
        options_frame.pack(pady=10)
        
        self.use_leet_var = tk.IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Use Leet Speak", variable=self.use_leet_var).grid(row=0, column=0, sticky='w')
        
        self.use_upper_var = tk.IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Use Uppercase", variable=self.use_upper_var).grid(row=0, column=1, sticky='w')
        
        self.use_lower_var = tk.IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Use Lowercase", variable=self.use_lower_var).grid(row=1, column=0, sticky='w')
        
        self.use_digits_var = tk.IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Use Digits", variable=self.use_digits_var).grid(row=1, column=1, sticky='w')
        
        self.use_special_var = tk.IntVar(value=1)
        ttk.Checkbutton(options_frame, text="Use Special Chars", variable=self.use_special_var).grid(row=2, column=0, sticky='w')
        
        
        length_frame = ttk.Frame(self.wordlist_frame)
        length_frame.pack(pady=10)
        
        ttk.Label(length_frame, text="Min Length:").grid(row=0, column=0)
        self.min_length = ttk.Spinbox(length_frame, from_=1, to=32, width=5)
        self.min_length.set(4)
        self.min_length.grid(row=0, column=1, padx=5)
        
        ttk.Label(length_frame, text="Max Length:").grid(row=0, column=2)
        self.max_length = ttk.Spinbox(length_frame, from_=1, to=32, width=5)
        self.max_length.set(12)
        self.max_length.grid(row=0, column=3, padx=5)
        
       
        ttk.Button(self.wordlist_frame, text="Generate Wordlist", 
                  command=self.generate_wordlist).pack(pady=10)
        
        
        self.wordlist_text = tk.Text(self.wordlist_frame, height=15, width=60)
        self.wordlist_text.pack(pady=10)
        
        ttk.Button(self.wordlist_frame, text="Export to File", 
                  command=self.export_wordlist).pack(pady=5)
        
        ttk.Button(self.wordlist_frame, text="Clear", 
                  command=self.clear_wordlist).pack(pady=5)

    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password to analyze")
            return
        
        analysis = self.analyzer.analyze_password(password)
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Password Analysis Results:\n\n")
        self.results_text.insert(tk.END, f"Password: {password}\n")
        self.results_text.insert(tk.END, f"Strength Score: {analysis['score']}/4\n")
        self.results_text.insert(tk.END, f"Estimated Crack Time: {analysis['crack_time']}\n")
        self.results_text.insert(tk.END, f"Guesses Needed: {analysis['guesses']}\n")
        self.results_text.insert(tk.END, f"Entropy (log10): {analysis['entropy']:.2f}\n\n")
        self.results_text.insert(tk.END, f"Feedback: {analysis['feedback']}\n\n")
        
        if analysis['suggestions']:
            self.results_text.insert(tk.END, "Suggestions:\n")
            for suggestion in analysis['suggestions']:
                self.results_text.insert(tk.END, f"- {suggestion}\n")

    def generate_wordlist(self):
        base_words = [word.strip() for word in self.base_words_entry.get().split(',') if word.strip()]
        years = [year.strip() for year in self.years_entry.get().split(',') if year.strip()]
        
        if not base_words:
            messagebox.showerror("Error", "Please enter at least one base word")
            return
        
        wordlist = self.generator.generate_wordlist(
            base_words=base_words,
            years=years,
            min_length=int(self.min_length.get()),
            max_length=int(self.max_length.get()),
            use_leet=self.use_leet_var.get() == 1,
            use_upper=self.use_upper_var.get() == 1,
            use_lower=self.use_lower_var.get() == 1,
            use_digits=self.use_digits_var.get() == 1,
            use_special=self.use_special_var.get() == 1
        )
        
        self.wordlist_text.delete(1.0, tk.END)
        self.wordlist_text.insert(tk.END, f"Generated {len(wordlist)} words:\n\n")
        self.wordlist_text.insert(tk.END, "\n".join(wordlist[:100]))  # Show first 100 words
        
        if len(wordlist) > 100:
            self.wordlist_text.insert(tk.END, f"\n\n... and {len(wordlist)-100} more words")

    def export_wordlist(self):
        wordlist = self.wordlist_text.get(1.0, tk.END).strip()
        if not wordlist or "Generated 0 words" in wordlist:
            messagebox.showerror("Error", "No wordlist to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save wordlist file"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Get all words (not just the preview)
                    words = self.wordlist_text.get(1.0, tk.END).split('\n')
                    # Skip the first line (header) and join the rest
                    f.write('\n'.join(words[2:]))
                messagebox.showinfo("Success", f"Wordlist saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def clear_analysis(self):
        self.password_entry.delete(0, tk.END)
        self.results_text.delete(1.0, tk.END)
        self.show_password_var.set(0)
        self.password_entry.config(show="*")

    def clear_wordlist(self):
        self.base_words_entry.delete(0, tk.END)
        self.years_entry.delete(0, tk.END)
        self.wordlist_text.delete(1.0, tk.END)
        self.use_leet_var.set(1)
        self.use_upper_var.set(1)
        self.use_lower_var.set(1)
        self.use_digits_var.set(1)
        self.use_special_var.set(1)
        self.min_length.set(4)
        self.max_length.set(12)

def cli_main():
    parser = argparse.ArgumentParser(description='Password Strength Analyzer & Wordlist Generator')
    subparsers = parser.add_subparsers(dest='command', required=True)
    

    analyze_parser = subparsers.add_parser('analyze', help='Analyze password strength')
    analyze_parser.add_argument('password', help='Password to analyze')
    
   
    wordlist_parser = subparsers.add_parser('generate', help='Generate custom wordlist')
    wordlist_parser.add_argument('-b', '--base', required=True, help='Base words (comma separated)')
    wordlist_parser.add_argument('-y', '--years', help='Years to append (comma separated)')
    wordlist_parser.add_argument('--no-leet', action='store_true', help='Disable leet speak variations')
    wordlist_parser.add_argument('--no-upper', action='store_true', help='Disable uppercase variations')
    wordlist_parser.add_argument('--no-lower', action='store_true', help='Disable lowercase variations')
    wordlist_parser.add_argument('--no-digits', action='store_true', help='Disable digit variations')
    wordlist_parser.add_argument('--no-special', action='store_true', help='Disable special character variations')
    wordlist_parser.add_argument('--min', type=int, default=4, help='Minimum password length')
    wordlist_parser.add_argument('--max', type=int, default=12, help='Maximum password length')
    wordlist_parser.add_argument('-o', '--output', help='Output file path')
    
    args = parser.parse_args()
    
    analyzer = PasswordAnalyzer()
    generator = WordlistGenerator()
    
    if args.command == 'analyze':
        analysis = analyzer.analyze_password(args.password)
        print("\nPassword Analysis Results:")
        print(f"Password: {args.password}")
        print(f"Strength Score: {analysis['score']}/4")
        print(f"Estimated Crack Time: {analysis['crack_time']}")
        print(f"Guesses Needed: {analysis['guesses']}")
        print(f"Entropy (log10): {analysis['entropy']:.2f}")
        print(f"\nFeedback: {analysis['feedback']}")
        if analysis['suggestions']:
            print("\nSuggestions:")
            for suggestion in analysis['suggestions']:
                print(f"- {suggestion}")
    
    elif args.command == 'generate':
        base_words = [word.strip() for word in args.base.split(',')]
        years = [year.strip() for year in args.years.split(',')] if args.years else []
        
        wordlist = generator.generate_wordlist(
            base_words=base_words,
            years=years,
            min_length=args.min,
            max_length=args.max,
            use_leet=not args.no_leet,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
            use_special=not args.no_special
        )
        
        print(f"Generated {len(wordlist)} words")
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write('\n'.join(wordlist))
                print(f"Wordlist saved to {args.output}")
            except Exception as e:
                print(f"Error saving file: {str(e)}")
        else:
            print("\nFirst 20 words:")
            print('\n'.join(wordlist[:20]))
            if len(wordlist) > 20:
                print(f"\n... and {len(wordlist)-20} more words")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        cli_main()
    else:
        root = tk.Tk()
        app = PasswordToolGUI(root)
        root.mainloop()
