import os
import pandas as pd
from deep_learning_functions import predict_batch, make_predictions

model_names = {
    'accessVector': 'distilroberta-base',
    'accessComplexity': 'distilroberta-base',
    'authentication': 'distilroberta-base',
    'confidentialityImpact': 'distilroberta-base',
    'integrityImpact': 'distilroberta-base',
    'availabilityImpact': 'distilroberta-base'
}

def calculate_scores(in_df):
    mapping = {
        'accessVector': {'LOCAL': 0.395, 'ADJACENT_NETWORK': 0.646, 'NETWORK': 1.0},
        'accessComplexity': {'HIGH': 0.35, 'MEDIUM': 0.61, 'LOW': 0.71},
        'authentication': {'MULTIPLE': 0.45, 'SINGLE': 0.56, 'NONE': 0.704},
        'confidentialityImpact': {'NONE': 0.0, 'PARTIAL': 0.275, 'COMPLETE': 0.660},
        'integrityImpact': {'NONE': 0.0, 'PARTIAL': 0.275, 'COMPLETE': 0.660},
        'availabilityImpact': {'NONE': 0.0, 'PARTIAL': 0.275, 'COMPLETE': 0.660}
    }
    predicted_df = in_df
    calculated_results = predicted_df.apply(lambda row: calculate_individual_scores(row, mapping), axis=1)
    calculated_df = pd.DataFrame(calculated_results.tolist())
    return calculated_df

def calculate_individual_scores(row, mapping):
    confidentialityImpact = mapping['confidentialityImpact'][row['confidentialityImpact']]
    integrityImpact = mapping['integrityImpact'][row['integrityImpact']]
    availabilityImpact = mapping['availabilityImpact'][row['availabilityImpact']]
    accessVector = mapping['accessVector'][row['accessVector']]
    accessComplexity = mapping['accessComplexity'][row['accessComplexity']]
    authentication = mapping['authentication'][row['authentication']]

    Impact = 10.41 * (1 - (1 - confidentialityImpact) * (1 - integrityImpact) * (1 - availabilityImpact))
    Exploitability = 20 * accessVector * accessComplexity * authentication
    f_Impact = 0 if Impact == 0 else 1.176
    BaseScore = (0.6 * Impact + 0.4 * Exploitability - 1.5) * f_Impact

    return {'cve': row['cve'], 'impactScore': Impact, 'exploitabilityScore': Exploitability, 'baseScore': BaseScore}



def analyze_and_predict(NAMESPACE):
    mapped_file_path = f"./data/mapped/{NAMESPACE}.csv"
    df = pd.read_csv(mapped_file_path, low_memory=False)
    df['has_cvss_v2'] = (df['accessVector'] != 'NF') & (df['baseScore'] != 'NF')
    df['has_cvss_v2'] = df['has_cvss_v2'].astype(int)
    print(f'Making predections using deep learning models ...')
    predicted_metrics = make_predictions(df,model_names, batch_size=256)
    for metric, predictions in predicted_metrics.items():
        df[f'p_{metric}'] = predictions
    
    print('Calculating the CVSS v2 impact,exploitability, and base scores ...')
    calculated_scores =  calculate_scores(df)
    for score_name, scores in calculated_scores.items():
        df[f'p_{score_name}'] = scores

    df.to_csv(f"./data/predicted/pred_{NAMESPACE}", index=False)
    print(f"Analysis, predictions, and calculations completed. Final results saved to '{NAMESPACE}'.")
    from error_table import calc_error
    calc_error(f"./data/predicted/pred_{NAMESPACE}")

