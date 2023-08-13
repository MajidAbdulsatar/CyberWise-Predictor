from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import pandas as pd
import os
model_names = {
    'accessVector': 'distilroberta-base',
    'accessComplexity': 'distilroberta-base',
    'authentication': 'distilroberta-base',
    'confidentialityImpact': 'distilroberta-base',
    'integrityImpact': 'distilroberta-base',
    'availabilityImpact': 'distilroberta-base'
}
device = torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu')
def predict_batch(batch_descriptions, model, tokenizer, class_i,label_mapping):
    encodings = tokenizer(batch_descriptions, truncation=True, padding=True, max_length=132)
    inputs = {key: torch.tensor(val) for key, val in encodings.items()}
    inputs['input_ids'] = inputs['input_ids'].to(device)
    inputs['attention_mask'] = inputs['attention_mask'].to(device)

    with torch.no_grad():
        outputs = model(**inputs)
        preds = outputs.logits.argmax(dim=-1).cpu().numpy()

    # Convert encoded labels to actual labels
    preds_labels = [label_mapping[class_i][pred] for pred in preds]
    return preds_labels
def make_predictions(input_file, model_names, batch_size=512):
    
    df =input_file
    descriptions = df['description'].tolist()
    cve_ids = df['cve'].tolist()

    # Create a DataFrame to store the results
    results_df = pd.DataFrame()
    results_df['cve'] = cve_ids

    # Load label mapping
    label_mapping_df = pd.read_csv('./data/label_mapping.csv')

    label_mapping = {}
    for class_name, group in label_mapping_df.groupby('class'):
        label_mapping[class_name] = {row['encoded_label']: row['actual_label'] for _, row in group.iterrows()}

    # Process each class and make predictions
    for class_i, model_name in model_names.items():
        print(f"Making predictions for class: {class_i}")
        model_path = os.path.join('tuned_models', f'{class_i}_model')
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        model.to(device)
        tokenizer = AutoTokenizer.from_pretrained(model_name)

        # Process descriptions in batches
        all_predictions = []
        for i in range(0, len(descriptions), batch_size):
            batch_descriptions = descriptions[i:i + batch_size]
            batch_predictions = predict_batch(batch_descriptions, model, tokenizer, class_i,label_mapping)
            all_predictions.extend(batch_predictions)

        results_df[class_i] = all_predictions
    return results_df