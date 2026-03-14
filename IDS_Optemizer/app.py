from flask import Flask, render_template, request, jsonify, send_file, url_for
import pandas as pd
import numpy as np
import random
import json
import os
import uuid
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import plotly.graph_objs as go
import plotly.utils
from io import BytesIO
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

# ============================================
# SYNTHETIC DATA GENERATOR
# ============================================
class DatasetGenerator:
    @staticmethod
    def generate_synthetic_dataset(n_samples=1000, noise_factor=0.1):
        """
        Generate synthetic IDS dataset with normal and intrusion traffic
        """
        data = []
        
        for i in range(n_samples):
            # Determine if this is normal or intrusion
            is_intrusion = random.random() < 0.3  # 30% intrusion traffic
            
            if is_intrusion:
                # Intrusion patterns
                # High failed logins (5-15)
                failed_logins = random.randint(5, 15) + random.gauss(0, noise_factor * 2)
                failed_logins = max(0, int(failed_logins))
                
                # High packet rate (800-2000)
                packet_rate = random.randint(800, 2000) + random.gauss(0, noise_factor * 100)
                packet_rate = max(0, int(packet_rate))
                
                # Very short or very long sessions
                if random.random() < 0.5:
                    session_time = random.uniform(1, 10)  # Very short
                else:
                    session_time = random.uniform(400, 600)  # Very long
                session_time = max(1, session_time)
                
                label = 1
            else:
                # Normal traffic patterns
                failed_logins = random.randint(0, 3) + random.gauss(0, noise_factor)
                failed_logins = max(0, int(failed_logins))
                
                packet_rate = random.randint(100, 600) + random.gauss(0, noise_factor * 50)
                packet_rate = max(0, int(packet_rate))
                
                session_time = random.uniform(30, 300) + random.gauss(0, noise_factor * 20)
                session_time = max(5, session_time)
                
                label = 0
            
            data.append({
                'failed_logins': failed_logins,
                'packet_rate': packet_rate,
                'session_time': round(session_time, 2),
                'label': label
            })
        
        return pd.DataFrame(data)

# ============================================
# RULE-BASED IDS
# ============================================
class RuleBasedIDS:
    def __init__(self, thresholds=None):
        """
        thresholds: [failed_logins_limit, packet_rate_limit, session_time_limit]
        """
        if thresholds is None:
            self.thresholds = [5, 1000, 300]  # Default reasonable thresholds
        else:
            self.thresholds = thresholds
    
    def predict(self, df):
        """
        Apply rule-based detection
        Rule: IF (failed_logins > limit OR packet_rate > limit OR session_time > limit) THEN intrusion
        """
        failed_limit, packet_limit, time_limit = self.thresholds
        
        predictions = (
            (df['failed_logins'] > failed_limit) |
            (df['packet_rate'] > packet_limit) |
            (df['session_time'] > time_limit)
        ).astype(int)
        
        return predictions.values
    
    @staticmethod
    def evaluate(y_true, y_pred):
        """Calculate detection metrics"""
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        
        # Detection Rate (True Positive Rate)
        detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # False Positive Rate
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        # Fitness = Detection Rate - False Positive Rate
        fitness = detection_rate - false_positive_rate
        
        return {
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
            'detection_rate': detection_rate,
            'false_positive_rate': false_positive_rate,
            'fitness': fitness
        }

# ============================================
# GENETIC ALGORITHM
# ============================================
class GeneticAlgorithm:
    def __init__(self, population_size=50, generations=30, mutation_rate=0.1, crossover_rate=0.8):
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        
        # Parameter bounds
        self.bounds = [
            (1, 15),      # failed_logins_limit
            (100, 2000),  # packet_rate_limit
            (50, 600)     # session_time_limit
        ]
    
    def create_individual(self):
        """Create a random individual (chromosome)"""
        return [random.uniform(low, high) for low, high in self.bounds]
    
    def mutate(self, individual):
        """Apply Gaussian mutation"""
        for i in range(len(individual)):
            if random.random() < self.mutation_rate:
                low, high = self.bounds[i]
                noise = random.gauss(0, (high - low) * 0.1)
                individual[i] = np.clip(individual[i] + noise, low, high)
        return individual
    
    def crossover(self, parent1, parent2):
        """Single-point crossover"""
        if random.random() < self.crossover_rate:
            point = random.randint(1, len(parent1) - 1)
            child1 = parent1[:point] + parent2[point:]
            child2 = parent2[:point] + parent1[point:]
            return child1, child2
        return parent1.copy(), parent2.copy()
    
    def tournament_selection(self, population, fitnesses, tournament_size=3):
        """Tournament selection"""
        selected = []
        for _ in range(len(population)):
            tournament = random.sample(list(zip(population, fitnesses)), tournament_size)
            winner = max(tournament, key=lambda x: x[1])[0]
            selected.append(winner)
        return selected
    
    def optimize(self, df, callback=None):
        """Run GA optimization"""
        # Initialize population
        population = [self.create_individual() for _ in range(self.population_size)]
        
        best_fitness_history = []
        avg_fitness_history = []
        
        for generation in range(self.generations):
            # Evaluate fitness
            fitnesses = []
            for individual in population:
                ids = RuleBasedIDS(individual)
                predictions = ids.predict(df)
                metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
                fitnesses.append(metrics['fitness'])
            
            best_fitness = max(fitnesses)
            avg_fitness = np.mean(fitnesses)
            best_fitness_history.append(best_fitness)
            avg_fitness_history.append(avg_fitness)
            
            if callback:
                callback(generation, best_fitness, avg_fitness, population[np.argmax(fitnesses)])
            
            # Selection
            selected = self.tournament_selection(population, fitnesses)
            
            # Crossover and Mutation
            new_population = []
            for i in range(0, len(selected), 2):
                parent1 = selected[i]
                parent2 = selected[i + 1] if i + 1 < len(selected) else selected[0]
                
                child1, child2 = self.crossover(parent1, parent2)
                child1 = self.mutate(child1)
                child2 = self.mutate(child2)
                
                new_population.extend([child1, child2])
            
            population = new_population[:self.population_size]
        
        # Return best solution
        best_idx = np.argmax([self._evaluate_individual(pop, df) for pop in population])
        best_solution = population[best_idx]
        
        ids = RuleBasedIDS(best_solution)
        predictions = ids.predict(df)
        final_metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
        
        return best_solution, final_metrics, best_fitness_history, avg_fitness_history
    
    def _evaluate_individual(self, individual, df):
        ids = RuleBasedIDS(individual)
        predictions = ids.predict(df)
        metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
        return metrics['fitness']

# ============================================
# GREEDY SEARCH
# ============================================
class GreedySearch:
    @staticmethod
    def optimize(df, initial_thresholds=None, step_size=0.05, max_iterations=100):
        """
        Greedy search for optimal thresholds
        """
        if initial_thresholds is None:
            current = [5.0, 1000.0, 300.0]
        else:
            current = initial_thresholds.copy()
        
        bounds = [(1, 15), (100, 2000), (50, 600)]
        
        # Evaluate initial
        ids = RuleBasedIDS(current)
        predictions = ids.predict(df)
        best_metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
        best_fitness = best_metrics['fitness']
        
        for iteration in range(max_iterations):
            improved = False
            
            # Try adjusting each parameter
            for i in range(3):
                # Try increase and decrease
                for direction in [1, -1]:
                    candidate = current.copy()
                    step = (bounds[i][1] - bounds[i][0]) * step_size * direction
                    candidate[i] = np.clip(candidate[i] + step, bounds[i][0], bounds[i][1])
                    
                    ids = RuleBasedIDS(candidate)
                    predictions = ids.predict(df)
                    metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
                    
                    if metrics['fitness'] > best_fitness:
                        current = candidate
                        best_fitness = metrics['fitness']
                        best_metrics = metrics
                        improved = True
                        break
                
                if improved:
                    break
            
            if not improved:
                break  # No improvement possible
        
        # Final evaluation
        ids = RuleBasedIDS(current)
        predictions = ids.predict(df)
        final_metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
        
        return current, final_metrics

# ============================================ cv
# A* SEARCH
# ============================================
class AStarSearch:
    class Node:
        def __init__(self, thresholds, g_cost, parent=None):
            self.thresholds = thresholds
            self.g_cost = g_cost  # Number of changes made
            self.parent = parent
            
            # Calculate h_cost (heuristic)
            ids = RuleBasedIDS(thresholds)
            predictions = ids.predict(df_for_search)
            metrics = RuleBasedIDS.evaluate(df_for_search['label'].values, predictions)
            self.h_cost = 1 - metrics['fitness']  # Lower fitness = higher heuristic cost
            
            self.f_cost = self.g_cost + self.h_cost
    
    @staticmethod
    def optimize(df, initial_thresholds=None, max_steps=50):
        global df_for_search
        df_for_search = df
        
        if initial_thresholds is None:
            initial = [5.0, 1000.0, 300.0]
        else:
            initial = initial_thresholds
        
        bounds = [(1, 15), (100, 2000), (50, 600)]
        step_size = 0.1
        
        open_list = []
        closed_set = set()
        
        start_node = AStarSearch.Node(initial, 0)
        open_list.append(start_node)
        
        best_node = start_node
        
        for step in range(max_steps):
            if not open_list:
                break
            
            # Get node with lowest f_cost
            current = min(open_list, key=lambda n: n.f_cost)
            open_list.remove(current)
            
            # Add to closed set
            closed_set.add(tuple(current.thresholds))
            
            if current.h_cost < best_node.h_cost:
                best_node = current
            
            # Generate neighbors
            for i in range(3):
                for direction in [1, -1]:
                    neighbor_thresholds = current.thresholds.copy()
                    step_val = (bounds[i][1] - bounds[i][0]) * step_size * direction
                    neighbor_thresholds[i] = np.clip(
                        neighbor_thresholds[i] + step_val, 
                        bounds[i][0], bounds[i][1]
                    )
                    
                    # Skip if already visited
                    if tuple(neighbor_thresholds) in closed_set:
                        continue
                    
                    neighbor = AStarSearch.Node(neighbor_thresholds, current.g_cost + 1, current)
                    open_list.append(neighbor)
        
        # Return best found
        ids = RuleBasedIDS(best_node.thresholds)
        predictions = ids.predict(df)
        final_metrics = RuleBasedIDS.evaluate(df['label'].values, predictions)
        
        return best_node.thresholds, final_metrics

# ============================================
# ROUTES
# ============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sample_dataset')
def sample_dataset():
    """Generate and download sample dataset"""
    df = DatasetGenerator.generate_synthetic_dataset(1000)
    
    # Save to file
    filename = f"sample_ids_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df.to_csv(filepath, index=False)
    
    return jsonify({
        'filename': filename,
        'rows': len(df),
        'preview': df.head(10).to_dict('records')
    })

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.endswith('.csv'):
        filename = f"uploaded_{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Load and validate
        try:
            df = pd.read_csv(filepath)
            required_cols = ['failed_logins', 'packet_rate', 'session_time', 'label']
            if not all(col in df.columns for col in required_cols):
                return jsonify({'error': 'CSV must contain columns: ' + ', '.join(required_cols)}), 400
            
            return jsonify({
                'filename': filename,
                'rows': len(df),
                'preview': df.head(10).to_dict('records')
            })
        except Exception as e:
            return jsonify({'error': f'Error reading CSV: {str(e)}'}), 400
    
    return jsonify({'error': 'Invalid file type. Please upload a CSV file.'}), 400

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    filename = data.get('filename')
    use_sample = data.get('use_sample', False)
    
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400
    
    # Load dataset
    try:
        if use_sample:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        else:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        df = pd.read_csv(filepath)
    except Exception as e:
        return jsonify({'error': f'Error loading dataset: {str(e)}'}), 400
    
    results = {}
    
    # 1. Fixed Thresholds
    fixed_thresholds = [5, 1000, 300]
    ids_fixed = RuleBasedIDS(fixed_thresholds)
    predictions_fixed = ids_fixed.predict(df)
    results['fixed'] = RuleBasedIDS.evaluate(df['label'].values, predictions_fixed)
    results['fixed']['thresholds'] = fixed_thresholds
    
    # 2. Greedy Search
    greedy_search = GreedySearch()
    greedy_thresholds, greedy_metrics = greedy_search.optimize(df)
    results['greedy'] = greedy_metrics
    results['greedy']['thresholds'] = greedy_thresholds
    
    # 3. A* Search
    astar_search = AStarSearch()
    astar_thresholds, astar_metrics = astar_search.optimize(df)
    results['astar'] = astar_metrics
    results['astar']['thresholds'] = astar_thresholds
    
    # 4. Genetic Algorithm
    ga_fitness_history = []
    ga_avg_history = []
    
    def ga_callback(generation, best_fitness, avg_fitness, best_individual):
        ga_fitness_history.append({
            'generation': generation,
            'best_fitness': best_fitness,
            'avg_fitness': avg_fitness
        })
    
    ga = GeneticAlgorithm(population_size=30, generations=20)
    ga_thresholds, ga_metrics, best_hist, avg_hist = ga.optimize(df, ga_callback)
    results['ga'] = ga_metrics
    results['ga']['thresholds'] = ga_thresholds
    
    # Generate visualizations
    charts = {}
    
    # Chart 1: Fitness Evolution (GA)
    if ga_fitness_history:
        fig_ga = go.Figure()
        
        generations = [h['generation'] for h in ga_fitness_history]
        best_fitnesses = [h['best_fitness'] for h in ga_fitness_history]
        avg_fitnesses = [h['avg_fitness'] for h in ga_fitness_history]
        
        fig_ga.add_trace(go.Scatter(
            x=generations, y=best_fitnesses,
            mode='lines+markers',
            name='Best Fitness',
            line=dict(color='#800020', width=3),
            marker=dict(size=6)
        ))
        
        fig_ga.add_trace(go.Scatter(
            x=generations, y=avg_fitnesses,
            mode='lines+markers',
            name='Average Fitness',
            line=dict(color='#808080', width=2, dash='dash'),
            marker=dict(size=4)
        ))
        
        fig_ga.update_layout(
            title='Genetic Algorithm: Fitness Evolution',
            xaxis_title='Generation',
            yaxis_title='Fitness Score',
            template='plotly_white',
            font=dict(family="Arial", size=12),
            showlegend=True,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )

        charts['ga_evolution'] = json.loads(fig_ga.to_json())
    # Chart 2: Comparison Chart
    methods = ['Fixed', 'Greedy', 'A*', 'GA']
    detection_rates = [
        results['fixed']['detection_rate'],
        results['greedy']['detection_rate'],
        results['astar']['detection_rate'],
        results['ga']['detection_rate']
    ]
    false_positive_rates = [
        results['fixed']['false_positive_rate'],
        results['greedy']['false_positive_rate'],
        results['astar']['false_positive_rate'],
        results['ga']['false_positive_rate']
    ]
    fitness_scores = [
        results['fixed']['fitness'],
        results['greedy']['fitness'],
        results['astar']['fitness'],
        results['ga']['fitness']
    ]
    
    fig_compare = go.Figure()
    
    fig_compare.add_trace(go.Bar(
        name='Detection Rate',
        x=methods,
        y=detection_rates,
        marker_color='#800020',
        opacity=0.8
    ))
    
    fig_compare.add_trace(go.Bar(
        name='(1 - False Positive Rate)',
        x=methods,
        y=[1 - fpr for fpr in false_positive_rates],
        marker_color='#404040',
        opacity=0.8
    ))
    
    fig_compare.add_trace(go.Scatter(
        name='Fitness Score',
        x=methods,
        y=fitness_scores,
        mode='lines+markers',
        line=dict(color='#000000', width=3),
        marker=dict(size=10, color='#000000'),
        yaxis='y2'
    ))
    
    fig_compare.update_layout(
        title='Performance Comparison Across Methods',
        xaxis_title='Method',
        yaxis=dict(title='Rate', side='left'),
        yaxis2=dict(title='Fitness Score', side='right', overlaying='y'),
        template='plotly_white',
        font=dict(family="Arial", size=12),
        showlegend=True,
        barmode='group',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )

    charts['comparison'] = json.loads(fig_compare.to_json())

    # Save results
    result_id = str(uuid.uuid4())
    results_data = {
        'result_id': result_id,
        'timestamp': datetime.now().isoformat(),
        'dataset_info': {
            'filename': filename,
            'rows': len(df),
            'intrusions': int(df['label'].sum()),
            'normal': int(len(df) - df['label'].sum())
        },
        'results': results,
        'charts': charts
    }
    
    # Save JSON results
    result_file = os.path.join(app.config['RESULTS_FOLDER'], f'result_{result_id}.json')
    with open(result_file, 'w') as f:
        json.dump(results_data, f, indent=2, default=str)
    
    return jsonify(results_data)

@app.route('/results/<result_id>')
def view_results(result_id):
    result_file = os.path.join(app.config['RESULTS_FOLDER'], f'result_{result_id}.json')
    if not os.path.exists(result_file):
        return "Results not found", 404
    
    with open(result_file, 'r') as f:
        results_data = json.load(f)
    
    return render_template('results.html', results=results_data)

@app.route('/download_report/<result_id>')
def download_report(result_id):
    result_file = os.path.join(app.config['RESULTS_FOLDER'], f'result_{result_id}.json')
    if not os.path.exists(result_file):
        return "Results not found", 404
    
    with open(result_file, 'r') as f:
        results_data = json.load(f)
    
    # Generate text report
    report_lines = [
        "INTRUSION DETECTION RULE OPTIMIZATION REPORT",
        "=" * 50,
        "",
        f"Generated: {results_data['timestamp']}",
        f"Dataset: {results_data['dataset_info']['filename']}",
        f"Total Records: {results_data['dataset_info']['rows']}",
        f"Intrusions: {results_data['dataset_info']['intrusions']}",
        f"Normal Traffic: {results_data['dataset_info']['normal']}",
        "",
        "RESULTS SUMMARY",
        "-" * 20,
        ""
    ]
    
    for method, key in [('Fixed Thresholds', 'fixed'), ('Greedy Search', 'greedy'), 
                       ('A* Search', 'astar'), ('Genetic Algorithm', 'ga')]:
        r = results_data['results'][key]
        report_lines.extend([
            f"{method}:",
            f"  Thresholds: Failed Logins={r['thresholds'][0]:.2f}, "
            f"Packet Rate={r['thresholds'][1]:.2f}, Session Time={r['thresholds'][2]:.2f}",
            f"  Detection Rate: {r['detection_rate']:.4f}",
            f"  False Positive Rate: {r['false_positive_rate']:.4f}",
            f"  Fitness Score: {r['fitness']:.4f}",
            ""
        ])
    
    # Find best method
    best_method = max(results_data['results'].items(), key=lambda x: x[1]['fitness'])
    report_lines.extend([
        "CONCLUSION",
        "-" * 15,
        f"Best performing method: {best_method[0].upper()}",
        f"Best fitness score: {best_method[1]['fitness']:.4f}",
        "",
        "METHODOLOGY",
        "-" * 15,
        "This analysis compares four approaches for optimizing intrusion detection rules:",
        "1. Fixed thresholds: Manual baseline using expert knowledge",
        "2. Greedy Search: Iteratively improves single parameters",
        "3. A* Search: Uses heuristic-guided exploration",
        "4. Genetic Algorithm: Evolutionary optimization with population-based search",
        "",
        "The fitness function maximizes detection rate while minimizing false positives:",
        "fitness = detection_rate - false_positive_rate"
    ])
    
    report_text = "\n".join(report_lines)
    
    # Save report
    report_file = os.path.join(app.config['RESULTS_FOLDER'], f'report_{result_id}.txt')
    with open(report_file, 'w') as f:
        f.write(report_text)
    
    return send_file(report_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
